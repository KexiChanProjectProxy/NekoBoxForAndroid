// libbox/dns.go

package libcore

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"

	mDNS "github.com/miekg/dns"
)

var rawQueryFunc func(networkHandle int64, request []byte) ([]byte, error)

type LocalDNSTransport interface {
	Raw() bool
	NetworkHandle() int64
	Lookup(ctx *ExchangeContext, network string, domain string) error
	Exchange(ctx *ExchangeContext, message []byte) error
}

var gLocalDNSTransport *platformLocalDNSTransport = nil

var (
	_ adapter.DNSTransport                    = (*platformLocalDNSTransport)(nil)
	_ adapter.DNSTransportWithPreferredDomain = (*platformLocalDNSTransport)(nil)
)

type platformLocalDNSTransport struct {
	dns.TransportAdapter
	iif               LocalDNSTransport
	raw               bool
	preferredResolver *local.PreferredDomainResolver
}

// newPlatformTransport creates the Android local DNS transport.
// logger may be nil (global instance used outside of a box), in which case the
// preferred domain resolver (hosts / neighbor lookups) is disabled.
func newPlatformTransport(ctx context.Context, logger log.ContextLogger, iif LocalDNSTransport, tag string, options option.LocalDNSServerOptions) (*platformLocalDNSTransport, error) {
	transport := &platformLocalDNSTransport{
		TransportAdapter: dns.NewTransportAdapterWithLocalOptions(constant.DNSTypeLocal, tag, options),
		iif:              iif,
		raw:              iif.Raw(),
	}
	if ctx != nil && logger != nil {
		preferredResolver, err := local.NewPreferredDomainResolver(ctx, logger, options)
		if err != nil {
			return nil, err
		}
		transport.preferredResolver = preferredResolver
	}
	return transport, nil
}

func (p *platformLocalDNSTransport) Start(stage adapter.StartStage) error {
	if p.preferredResolver != nil {
		p.preferredResolver.Start(stage)
	}
	return nil
}

func (p *platformLocalDNSTransport) Close() error {
	return nil
}

func (p *platformLocalDNSTransport) Reset() {
}

func (p *platformLocalDNSTransport) PreferredDomain(domain string) bool {
	if p.preferredResolver == nil {
		return false
	}
	return p.preferredResolver.PreferredDomain(domain)
}

func (p *platformLocalDNSTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(p.Exchange(ctx, message))
	}()
}

func (p *platformLocalDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if p.preferredResolver != nil {
		if localResponse := p.preferredResolver.Lookup(message); localResponse != nil {
			return localResponse, nil
		}
	}
	if p.raw && rawQueryFunc != nil {
		// Raw - Android 10 及以上才有

		messageBytes, err := message.Pack()
		if err != nil {
			return nil, err
		}
		msg, err := rawQueryFunc(p.iif.NetworkHandle(), messageBytes)
		if err != nil {
			return nil, err
		}
		responseMessage := new(mDNS.Msg)
		err = responseMessage.Unpack(msg)
		if err != nil {
			return nil, err
		}
		return responseMessage, nil
	} else {
		// Lookup - Android 10 以下

		question := message.Question[0]
		var network string
		switch question.Qtype {
		case mDNS.TypeA:
			network = "ip4"
		case mDNS.TypeAAAA:
			network = "ip6"
		default:
			return nil, E.New("only IP queries are supported by current version of Android")
		}

		done := make(chan struct{})
		response := &ExchangeContext{
			context: ctx,
			done: sync.OnceFunc(func() {
				close(done)
			}),
		}

		var responseAddrs []netip.Addr
		var group task.Group
		group.Append0(func(ctx context.Context) error {
			err := p.iif.Lookup(response, network, question.Name)
			if err != nil {
				return err
			}
			select {
			case <-done:
			case <-ctx.Done():
				return context.Canceled
			}
			if response.error != nil {
				return response.error
			}
			responseAddrs = response.addresses
			return nil
		})
		err := group.Run(ctx)
		if err != nil {
			return nil, err
		}
		return dns.FixedResponse(message.Id, question, responseAddrs, constant.DefaultDNSTTL), nil
	}
}

type Func interface {
	Invoke() error
}

type ExchangeContext struct {
	context   context.Context
	message   mDNS.Msg
	addresses []netip.Addr
	error     error
	done      func()
}

func (c *ExchangeContext) OnCancel(callback Func) {
	go func() {
		<-c.context.Done()
		callback.Invoke()
	}()
}

func (c *ExchangeContext) Success(result string) {
	c.addresses = common.Map(common.Filter(strings.Split(result, "\n"), func(it string) bool {
		return !common.IsEmpty(it)
	}), func(it string) netip.Addr {
		return M.ParseSocksaddrHostPort(it, 0).Unwrap().Addr
	})
}

func (c *ExchangeContext) RawSuccess(result []byte) {
	err := c.message.Unpack(result)
	if err != nil {
		c.error = E.Cause(err, "parse response")
	}
	c.done()
}

func (c *ExchangeContext) ErrorCode(code int32) {
	c.error = dns.RcodeError(code)
	c.done()
}

func (c *ExchangeContext) ErrnoCode(code int32) {
	c.error = syscall.Errno(code)
	c.done()
}
