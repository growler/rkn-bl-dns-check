package main

import (
	"net"
	"bufio"
	"os"
	"sync"
	"time"
	"fmt"

	"github.com/miekg/dns"
	"github.com/asergeyev/nradix"
	"flag"
)

type hostaddr struct {
	host string
	addr net.IP
	err  error
}

var (
	server     string
	localIpStr string
	dialer     *net.Dialer
	timeout    time.Duration
	printErrs  bool
	printHosts bool
	workers    int
)

func init() {
	flag.BoolVar(&printHosts, "printHosts", false, "also prints hosts")
	flag.IntVar(&workers, "workers", 64, "number of workers")
	flag.BoolVar(&printErrs, "errs", false, "print resolving errors to stderr")
	flag.StringVar(&server, "server", "", "dns server to use")
	flag.DurationVar(&timeout, "timeout", 10 * time.Second, "single query timeout")
	flag.StringVar(&localIpStr, "localip", "", "local ip address to query from")
}

func main() {
	flag.Parse()
	if server == "" {
		flag.PrintDefaults()
		fmt.Println("please specify server address")
		os.Exit(1)
	} else {
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(server, "53")
		}
		if _, err := net.ResolveUDPAddr("udp", server); err != nil {
			fmt.Printf("invalid server address: %s\n", err)
			os.Exit(1)
		}
	}
	dialer = &net.Dialer{}
	if localIpStr != "" {
		var err error
		localAddresses, err := net.InterfaceAddrs()
		if err != nil {
			fmt.Printf("can't get list of local ip addresses: %s\n", err)
			os.Exit(1)
		}
		if lip := net.ParseIP(localIpStr); lip == nil {
			flag.PrintDefaults()
			fmt.Printf("localip must be a local ip address (%s)\n", localIpStr)
			os.Exit(1)
		} else {
			for _, localAddress := range localAddresses {
				if localIpAddress, ok := localAddress.(*net.IPNet); ok {
					if localIpAddress.IP.Equal(lip) {
						dialer.LocalAddr = &net.UDPAddr{IP: lip}
						goto Found
					}
				}
			}
		}
		os.Exit(1)
	Found:
	}
	if conn, err := dialer.Dial("udp", server); err != nil {
		flag.PrintDefaults()
		if localIpStr != "" {
			fmt.Printf("can't dial server %s using %s local address: %s", server, localIpStr, err)
		} else {
			fmt.Printf("can't dial server %s: %s", server, err)
		}
		os.Exit(1)
	} else {
		conn.Close()
	}
	domList := make(map[string]bool, 65536)
	addrTree := nradix.NewTree(65536)
	inp := bufio.NewScanner(os.Stdin)
	rc := make(chan hostaddr)
	rq := make(chan int, workers)
	pipes := make([]chan string, workers)
	wg := sync.WaitGroup{}
	for i := range pipes {
		pipes[i] = make(chan string)
		go func(pipe chan string, id int) {
			wg.Add(1)
			defer wg.Done()
			rq <- id
			c := &dns.Client{
				Dialer: dialer,
			}
			for domain := range pipe {
				dl := time.Now().Add(timeout)
				srvrs := make([]string, 1)
				srvrs[0] = server
			Query:
				for {
					if len(srvrs) == 0 {
						rc <- hostaddr{
							host: domain,
							err:  fmt.Errorf("no servers left to try"),
						}
						break Query
					}
					srv := srvrs[0]
					copy(srvrs, srvrs[1:])
					srvrs = srvrs[0 : len(srvrs)-1]
					m := &dns.Msg{
						MsgHdr: dns.MsgHdr{
							Id:               dns.Id(),
							RecursionDesired: true,
							Opcode:           dns.OpcodeQuery,
						},
						Question: []dns.Question{
							{Name: dns.Fqdn(domain), Qtype: dns.TypeA, Qclass: dns.ClassINET},
						},
					}
				Retry:
					to := dl.Sub(time.Now())
					if to < 0 {
						rc <- hostaddr{
							host: domain,
							err:  fmt.Errorf("timeout"),
						}
						break Query
					}
					c.Timeout = to
					r, _, err := c.Exchange(m, srv)
					if err == dns.ErrTruncated {
						o := &dns.OPT{
							Hdr: dns.RR_Header{
								Name:   ".",
								Rrtype: dns.TypeOPT,
							},
						}
						o.SetUDPSize(dns.DefaultMsgSize)
						m.Extra = append(m.Extra, o)
						goto Retry
					} else if err != nil {
						rc <- hostaddr{
							host: domain,
							err:  err,
						}
						break Query
					} else {
						if r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeServerFailure {
							break Query
						} else if r.Rcode != dns.RcodeSuccess {
							rc <- hostaddr{
								host: domain,
								err: func() error {
									if r.Rcode < len(dns.RcodeToString) {
										return fmt.Errorf("%s", dns.RcodeToString[r.Rcode])
									} else {
										return fmt.Errorf("unknown dns Rcode %d", r.Rcode)
									}
								}(),
							}
							break Query
						}
						if len(r.Answer) > 0 {
							for i := range r.Answer {
								switch addr := r.Answer[i].(type) {
								case *dns.A:
									rc <- hostaddr{
										host: domain,
										addr: addr.A,
									}
								}
							}
							break Query
						} else if len(r.Extra) > 0 {
							srvrs = srvrs[0:0]
							for i := range r.Extra {
								switch rec := r.Extra[i].(type) {
								case *dns.A:
									srvrs = append(srvrs, net.JoinHostPort(rec.A.String(), "53"))
									continue Query
								}
							}
						}
					}
				}
				rq <- id
			}
		}(pipes[i], i)
	}
	go func() {
		for inp.Scan() {
			domain := inp.Text()
			if _, ok := domList[domain]; !ok {
				domList[domain] = true
				pipes[<-rq]<-domain
			}
		}
		for i := range pipes {
			close(pipes[i])
		}
		wg.Wait()
		close(rc)
	}()
	for {
		if r, more := <-rc; more {
			if r.err != nil {
				if printErrs {
					fmt.Fprintf(os.Stderr, "error resolving %s: %s\n", r.host, r.err)
				}
				continue
			}
			addr := r.addr.String()
			if !printHosts {
				if f, ok := addrTree.FindCIDR(addr); f != nil && ok == nil {
					continue
				} else {
					addrTree.AddCIDR(addr, true)
				}
			} else {
				os.Stdout.WriteString(r.host)
				os.Stdout.Write([]byte("\t"))
			}
			os.Stdout.WriteString(addr)
			os.Stdout.Write([]byte("\n"))
		} else {
			break
		}
	}
}