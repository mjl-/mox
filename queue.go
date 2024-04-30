package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mjl-/mox/queue"
)

func xctlwriteJSON(ctl *ctl, v any) {
	fbuf, err := json.Marshal(v)
	xcheckf(err, "marshal as json to ctl")
	ctl.xwrite(string(fbuf))
}

func cmdQueueHoldrulesList(c *cmd) {
	c.help = `List hold rules for the delivery queue.

Messages submitted to the queue that match a hold rule will be marked as on hold
and not scheduled for delivery.
`
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHoldrulesList(xctl())
}

func ctlcmdQueueHoldrulesList(ctl *ctl) {
	ctl.xwrite("queueholdruleslist")
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueHoldrulesAdd(c *cmd) {
	c.params = "[ruleflags]"
	c.help = `Add hold rule for the delivery queue.

Add a hold rule to mark matching newly submitted messages as on hold. Set the
matching rules with the flags. Don't specify any flags to match all submitted
messages.
`
	var account, senderDomain, recipientDomain string
	c.flag.StringVar(&account, "account", "", "account submitting the message")
	c.flag.StringVar(&senderDomain, "senderdom", "", "sender domain")
	c.flag.StringVar(&recipientDomain, "recipientdom", "", "recipient domain")
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHoldrulesAdd(xctl(), account, senderDomain, recipientDomain)
}

func ctlcmdQueueHoldrulesAdd(ctl *ctl, account, senderDomain, recipientDomain string) {
	ctl.xwrite("queueholdrulesadd")
	ctl.xwrite(account)
	ctl.xwrite(senderDomain)
	ctl.xwrite(recipientDomain)
	ctl.xreadok()
}

func cmdQueueHoldrulesRemove(c *cmd) {
	c.params = "ruleid"
	c.help = `Remove hold rule for the delivery queue.

Remove a hold rule by its id.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	xcheckf(err, "parsing id")
	mustLoadConfig()
	ctlcmdQueueHoldrulesRemove(xctl(), id)
}

func ctlcmdQueueHoldrulesRemove(ctl *ctl, id int64) {
	ctl.xwrite("queueholdrulesremove")
	ctl.xwrite(fmt.Sprintf("%d", id))
	ctl.xreadok()
}

// flagFilterSort is used by many of the queue commands to accept flags for
// filtering the messages the operation applies to.
func flagFilterSort(fs *flag.FlagSet, f *queue.Filter, s *queue.Sort) {
	fs.Func("ids", "comma-separated list of message IDs", func(v string) error {
		for _, s := range strings.Split(v, ",") {
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return err
			}
			f.IDs = append(f.IDs, id)
		}
		return nil
	})
	fs.IntVar(&f.Max, "n", 0, "number of messages to return")
	fs.StringVar(&f.Account, "account", "", "account that queued the message")
	fs.StringVar(&f.From, "from", "", `from address of message, use "@example.com" to match all messages for a domain`)
	fs.StringVar(&f.To, "to", "", `recipient address of message, use "@example.com" to match all messages for a domain`)
	fs.StringVar(&f.Submitted, "submitted", "", `filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.StringVar(&f.NextAttempt, "nextattempt", "", `filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.Func("transport", "transport to use for messages, empty string sets the default behaviour", func(v string) error {
		f.Transport = &v
		return nil
	})
	fs.Func("hold", "true or false, whether to match only messages that are (not) on hold", func(v string) error {
		var hold bool
		if v == "true" {
			hold = true
		} else if v == "false" {
			hold = false
		} else {
			return fmt.Errorf("bad value %q", v)
		}
		f.Hold = &hold
		return nil
	})
	if s != nil {
		fs.Func("sort", `field to sort by, "nextattempt" (default) or "queued"`, func(v string) error {
			switch v {
			case "nextattempt":
				s.Field = "NextAttempt"
			case "queued":
				s.Field = "Queued"
			default:
				return fmt.Errorf("unknown value %q", v)
			}
			return nil
		})
		fs.BoolVar(&s.Asc, "asc", false, "sort ascending instead of descending (default)")
	}
}

// flagRetiredFilterSort has filters for retired messages.
func flagRetiredFilterSort(fs *flag.FlagSet, f *queue.RetiredFilter, s *queue.RetiredSort) {
	fs.Func("ids", "comma-separated list of retired message IDs", func(v string) error {
		for _, s := range strings.Split(v, ",") {
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return err
			}
			f.IDs = append(f.IDs, id)
		}
		return nil
	})
	fs.IntVar(&f.Max, "n", 0, "number of messages to return")
	fs.StringVar(&f.Account, "account", "", "account that queued the message")
	fs.StringVar(&f.From, "from", "", `from address of message, use "@example.com" to match all messages for a domain`)
	fs.StringVar(&f.To, "to", "", `recipient address of message, use "@example.com" to match all messages for a domain`)
	fs.StringVar(&f.Submitted, "submitted", "", `filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.StringVar(&f.LastActivity, "lastactivity", "", `filter by time of last activity relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.Func("transport", "transport to use for messages, empty string sets the default behaviour", func(v string) error {
		f.Transport = &v
		return nil
	})
	fs.Func("result", `"success" or "failure" as result of delivery`, func(v string) error {
		switch v {
		case "success":
			t := true
			f.Success = &t
		case "failure":
			t := false
			f.Success = &t
		default:
			return fmt.Errorf("bad argument %q, need success or failure", v)
		}
		return nil
	})
	if s != nil {
		fs.Func("sort", `field to sort by, "lastactivity" (default) or "queued"`, func(v string) error {
			switch v {
			case "lastactivity":
				s.Field = "LastActivity"
			case "queued":
				s.Field = "Queued"
			default:
				return fmt.Errorf("unknown value %q", v)
			}
			return nil
		})
		fs.BoolVar(&s.Asc, "asc", false, "sort ascending instead of descending (default)")
	}
}

func cmdQueueList(c *cmd) {
	c.params = "[filtersortflags]"
	c.help = `List matching messages in the delivery queue.

Prints the message with its ID, last and next delivery attempts, last error.
`
	var f queue.Filter
	var s queue.Sort
	flagFilterSort(c.flag, &f, &s)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueList(xctl(), f, s)
}

func ctlcmdQueueList(ctl *ctl, f queue.Filter, s queue.Sort) {
	ctl.xwrite("queuelist")
	xctlwriteJSON(ctl, f)
	xctlwriteJSON(ctl, s)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueHold(c *cmd) {
	c.params = "[filterflags]"
	c.help = `Mark matching messages on hold.

Messages that are on hold are not delivered until marked as off hold again, or
otherwise handled by the admin.
`
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHoldSet(xctl(), f, true)
}

func cmdQueueUnhold(c *cmd) {
	c.params = "[filterflags]"
	c.help = `Mark matching messages off hold.

Once off hold, messages can be delivered according to their current next
delivery attempt. See the "queue schedule" command.
`
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHoldSet(xctl(), f, false)
}

func ctlcmdQueueHoldSet(ctl *ctl, f queue.Filter, hold bool) {
	ctl.xwrite("queueholdset")
	xctlwriteJSON(ctl, f)
	if hold {
		ctl.xwrite("true")
	} else {
		ctl.xwrite("false")
	}
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages changed\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueSchedule(c *cmd) {
	c.params = "[filterflags] [-now] duration"
	c.help = `Change next delivery attempt for matching messages.

The next delivery attempt is adjusted by the duration parameter. If the -now
flag is set, the new delivery attempt is set to the duration added to the
current time, instead of added to the current scheduled time.

Schedule immediate delivery with "mox queue schedule -now 0".
`
	var fromNow bool
	c.flag.BoolVar(&fromNow, "now", false, "schedule for duration relative to current time instead of relative to current next delivery attempt for messages")
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	d, err := time.ParseDuration(args[0])
	xcheckf(err, "parsing duration %q", args[0])
	mustLoadConfig()
	ctlcmdQueueSchedule(xctl(), f, fromNow, d)
}

func ctlcmdQueueSchedule(ctl *ctl, f queue.Filter, fromNow bool, d time.Duration) {
	ctl.xwrite("queueschedule")
	xctlwriteJSON(ctl, f)
	if fromNow {
		ctl.xwrite("yes")
	} else {
		ctl.xwrite("")
	}
	ctl.xwrite(d.String())
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s message(s) rescheduled\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueTransport(c *cmd) {
	c.params = "[filterflags] transport"
	c.help = `Set transport for matching messages.

By default, the routing rules determine how a message is delivered. The default
and common case is direct delivery with SMTP. Messages can get a previously
configured transport assigned to use for delivery, e.g. using submission to
another mail server or with connections over a SOCKS proxy.
`
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueTransport(xctl(), f, args[0])
}

func ctlcmdQueueTransport(ctl *ctl, f queue.Filter, transport string) {
	ctl.xwrite("queuetransport")
	xctlwriteJSON(ctl, f)
	ctl.xwrite(transport)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s message(s) changed\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueRequireTLS(c *cmd) {
	c.params = "[filterflags] {yes | no | default}"
	c.help = `Set TLS requirements for delivery of matching messages.

Value "yes" is handled as if the RequireTLS extension was specified during
submission.

Value "no" is handled as if the message has a header "TLS-Required: No". This
header is not added by the queue. If messages without this header are relayed
through other mail servers they will apply their own default TLS policy.

Value "default" is the default behaviour, currently for unverified opportunistic
TLS.
`
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	var tlsreq *bool
	switch args[0] {
	case "yes":
		v := true
		tlsreq = &v
	case "no":
		v := false
		tlsreq = &v
	case "default":
	default:
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueRequireTLS(xctl(), f, tlsreq)
}

func ctlcmdQueueRequireTLS(ctl *ctl, f queue.Filter, tlsreq *bool) {
	ctl.xwrite("queuerequiretls")
	xctlwriteJSON(ctl, f)
	var req string
	if tlsreq == nil {
		req = ""
	} else if *tlsreq {
		req = "true"
	} else {
		req = "false"
	}
	ctl.xwrite(req)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s message(s) changed\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueFail(c *cmd) {
	c.params = "[filterflags]"
	c.help = `Fail delivery of matching messages, delivering DSNs.

Failing a message is handled similar to how delivery is given up after all
delivery attempts failed. The DSN (delivery status notification) message
contains a line saying the message was canceled by the admin.
`
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueFail(xctl(), f)
}

func ctlcmdQueueFail(ctl *ctl, f queue.Filter) {
	ctl.xwrite("queuefail")
	xctlwriteJSON(ctl, f)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s message(s) marked as failed\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueDrop(c *cmd) {
	c.params = "[filterflags]"
	c.help = `Remove matching messages from the queue.

Dangerous operation, this completely removes the message. If you want to store
the message, use "queue dump" before removing.
`
	var f queue.Filter
	flagFilterSort(c.flag, &f, nil)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueDrop(xctl(), f)
}

func ctlcmdQueueDrop(ctl *ctl, f queue.Filter) {
	ctl.xwrite("queuedrop")
	xctlwriteJSON(ctl, f)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s message(s) dropped\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueDump(c *cmd) {
	c.params = "id"
	c.help = `Dump a message from the queue.

The message is printed to stdout and is in standard internet mail format.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueDump(xctl(), args[0])
}

func ctlcmdQueueDump(ctl *ctl, id string) {
	ctl.xwrite("queuedump")
	ctl.xwrite(id)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueSuppressList(c *cmd) {
	c.params = "[-account account]"
	c.help = `Print addresses in suppression list.`
	var account string
	c.flag.StringVar(&account, "account", "", "only show suppression list for this account")
	args := c.Parse()
	if len(args) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueSuppressList(xctl(), account)
}

func ctlcmdQueueSuppressList(ctl *ctl, account string) {
	ctl.xwrite("queuesuppresslist")
	ctl.xwrite(account)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueSuppressAdd(c *cmd) {
	c.params = "account address"
	c.help = `Add address to suppression list for account.`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueSuppressAdd(xctl(), args[0], args[1])
}

func ctlcmdQueueSuppressAdd(ctl *ctl, account, address string) {
	ctl.xwrite("queuesuppressadd")
	ctl.xwrite(account)
	ctl.xwrite(address)
	ctl.xreadok()
}

func cmdQueueSuppressRemove(c *cmd) {
	c.params = "account address"
	c.help = `Remove address from suppression list for account.`
	args := c.Parse()
	if len(args) != 2 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueSuppressRemove(xctl(), args[0], args[1])
}

func ctlcmdQueueSuppressRemove(ctl *ctl, account, address string) {
	ctl.xwrite("queuesuppressremove")
	ctl.xwrite(account)
	ctl.xwrite(address)
	ctl.xreadok()
}

func cmdQueueSuppressLookup(c *cmd) {
	c.params = "[-account account] address"
	c.help = `Check if address is present in suppression list, for any or specific account.`
	var account string
	c.flag.StringVar(&account, "account", "", "only check address in specified account")
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueSuppressLookup(xctl(), account, args[0])
}

func ctlcmdQueueSuppressLookup(ctl *ctl, account, address string) {
	ctl.xwrite("queuesuppresslookup")
	ctl.xwrite(account)
	ctl.xwrite(address)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueRetiredList(c *cmd) {
	c.params = "[filtersortflags]"
	c.help = `List matching messages in the retired queue.

Prints messages with their ID and results.
`
	var f queue.RetiredFilter
	var s queue.RetiredSort
	flagRetiredFilterSort(c.flag, &f, &s)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueRetiredList(xctl(), f, s)
}

func ctlcmdQueueRetiredList(ctl *ctl, f queue.RetiredFilter, s queue.RetiredSort) {
	ctl.xwrite("queueretiredlist")
	xctlwriteJSON(ctl, f)
	xctlwriteJSON(ctl, s)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueRetiredPrint(c *cmd) {
	c.params = "id"
	c.help = `Print a message from the retired queue.

Prints a JSON representation of the information from the retired queue.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueRetiredPrint(xctl(), args[0])
}

func ctlcmdQueueRetiredPrint(ctl *ctl, id string) {
	ctl.xwrite("queueretiredprint")
	ctl.xwrite(id)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

// note: outgoing hook events are in queue/hooks.go, mox-/config.go, queue.go and webapi/gendoc.sh. keep in sync.

// flagHookFilterSort is used by many of the queue commands to accept flags for
// filtering the webhooks the operation applies to.
func flagHookFilterSort(fs *flag.FlagSet, f *queue.HookFilter, s *queue.HookSort) {
	fs.Func("ids", "comma-separated list of webhook IDs", func(v string) error {
		for _, s := range strings.Split(v, ",") {
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return err
			}
			f.IDs = append(f.IDs, id)
		}
		return nil
	})
	fs.IntVar(&f.Max, "n", 0, "number of webhooks to return")
	fs.StringVar(&f.Account, "account", "", "account that queued the message/webhook")
	fs.StringVar(&f.Submitted, "submitted", "", `filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.StringVar(&f.NextAttempt, "nextattempt", "", `filter by time of next delivery attempt relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.Func("event", `event this webhook is about: incoming, delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized`, func(v string) error {
		switch v {
		case "incoming", "delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized":
			f.Event = v
		default:
			return fmt.Errorf("invalid parameter %q", v)
		}
		return nil
	})
	if s != nil {
		fs.Func("sort", `field to sort by, "nextattempt" (default) or "queued"`, func(v string) error {
			switch v {
			case "nextattempt":
				s.Field = "NextAttempt"
			case "queued":
				s.Field = "Queued"
			default:
				return fmt.Errorf("unknown value %q", v)
			}
			return nil
		})
		fs.BoolVar(&s.Asc, "asc", false, "sort ascending instead of descending (default)")
	}
}

// flagHookRetiredFilterSort is used by many of the queue commands to accept flags
// for filtering the webhooks the operation applies to.
func flagHookRetiredFilterSort(fs *flag.FlagSet, f *queue.HookRetiredFilter, s *queue.HookRetiredSort) {
	fs.Func("ids", "comma-separated list of retired webhook IDs", func(v string) error {
		for _, s := range strings.Split(v, ",") {
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return err
			}
			f.IDs = append(f.IDs, id)
		}
		return nil
	})
	fs.IntVar(&f.Max, "n", 0, "number of webhooks to return")
	fs.StringVar(&f.Account, "account", "", "account that queued the message/webhook")
	fs.StringVar(&f.Submitted, "submitted", "", `filter by time of submission relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.StringVar(&f.LastActivity, "lastactivity", "", `filter by time of last activity relative to now, value must start with "<" (before now) or ">" (after now)`)
	fs.Func("event", `event this webhook is about: incoming, delivered, suppressed, delayed, failed, relayed, expanded, canceled, unrecognized`, func(v string) error {
		switch v {
		case "incoming", "delivered", "suppressed", "delayed", "failed", "relayed", "expanded", "canceled", "unrecognized":
			f.Event = v
		default:
			return fmt.Errorf("invalid parameter %q", v)
		}
		return nil
	})
	if s != nil {
		fs.Func("sort", `field to sort by, "lastactivity" (default) or "queued"`, func(v string) error {
			switch v {
			case "lastactivity":
				s.Field = "LastActivity"
			case "queued":
				s.Field = "Queued"
			default:
				return fmt.Errorf("unknown value %q", v)
			}
			return nil
		})
		fs.BoolVar(&s.Asc, "asc", false, "sort ascending instead of descending (default)")
	}
}

func cmdQueueHookList(c *cmd) {
	c.params = "[filtersortflags]"
	c.help = `List matching webhooks in the queue.

Prints list of webhooks, their IDs and basic information.
`
	var f queue.HookFilter
	var s queue.HookSort
	flagHookFilterSort(c.flag, &f, &s)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHookList(xctl(), f, s)
}

func ctlcmdQueueHookList(ctl *ctl, f queue.HookFilter, s queue.HookSort) {
	ctl.xwrite("queuehooklist")
	xctlwriteJSON(ctl, f)
	xctlwriteJSON(ctl, s)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueHookSchedule(c *cmd) {
	c.params = "[filterflags] duration"
	c.help = `Change next delivery attempt for matching webhooks.

The next delivery attempt is adjusted by the duration parameter. If the -now
flag is set, the new delivery attempt is set to the duration added to the
current time, instead of added to the current scheduled time.

Schedule immediate delivery with "mox queue schedule -now 0".
`
	var fromNow bool
	c.flag.BoolVar(&fromNow, "now", false, "schedule for duration relative to current time instead of relative to current next delivery attempt for webhooks")
	var f queue.HookFilter
	flagHookFilterSort(c.flag, &f, nil)
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	d, err := time.ParseDuration(args[0])
	xcheckf(err, "parsing duration %q", args[0])
	mustLoadConfig()
	ctlcmdQueueHookSchedule(xctl(), f, fromNow, d)
}

func ctlcmdQueueHookSchedule(ctl *ctl, f queue.HookFilter, fromNow bool, d time.Duration) {
	ctl.xwrite("queuehookschedule")
	xctlwriteJSON(ctl, f)
	if fromNow {
		ctl.xwrite("yes")
	} else {
		ctl.xwrite("")
	}
	ctl.xwrite(d.String())
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s webhook(s) rescheduled\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueHookCancel(c *cmd) {
	c.params = "[filterflags]"
	c.help = `Fail delivery of matching webhooks.`
	var f queue.HookFilter
	flagHookFilterSort(c.flag, &f, nil)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHookCancel(xctl(), f)
}

func ctlcmdQueueHookCancel(ctl *ctl, f queue.HookFilter) {
	ctl.xwrite("queuehookcancel")
	xctlwriteJSON(ctl, f)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s webhook(s)s marked as canceled\n", ctl.xread())
	} else {
		log.Fatalf("%s", line)
	}
}

func cmdQueueHookPrint(c *cmd) {
	c.params = "id"
	c.help = `Print details of a webhook from the queue.

The webhook is printed to stdout as JSON.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHookPrint(xctl(), args[0])
}

func ctlcmdQueueHookPrint(ctl *ctl, id string) {
	ctl.xwrite("queuehookprint")
	ctl.xwrite(id)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueHookRetiredList(c *cmd) {
	c.params = "[filtersortflags]"
	c.help = `List matching webhooks in the retired queue.

Prints list of retired webhooks, their IDs and basic information.
`
	var f queue.HookRetiredFilter
	var s queue.HookRetiredSort
	flagHookRetiredFilterSort(c.flag, &f, &s)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHookRetiredList(xctl(), f, s)
}

func ctlcmdQueueHookRetiredList(ctl *ctl, f queue.HookRetiredFilter, s queue.HookRetiredSort) {
	ctl.xwrite("queuehookretiredlist")
	xctlwriteJSON(ctl, f)
	xctlwriteJSON(ctl, s)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}

func cmdQueueHookRetiredPrint(c *cmd) {
	c.params = "id"
	c.help = `Print details of a webhook from the retired queue.

The retired webhook is printed to stdout as JSON.
`
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHookRetiredPrint(xctl(), args[0])
}

func ctlcmdQueueHookRetiredPrint(ctl *ctl, id string) {
	ctl.xwrite("queuehookretiredprint")
	ctl.xwrite(id)
	ctl.xreadok()
	if _, err := io.Copy(os.Stdout, ctl.reader()); err != nil {
		log.Fatalf("%s", err)
	}
}
