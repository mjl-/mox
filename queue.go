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

// flagFilter is used by many of the queue commands to accept flags for filtering
// the messages the operation applies to.
func flagFilter(fs *flag.FlagSet, f *queue.Filter) {
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
}

func cmdQueueList(c *cmd) {
	c.params = "[filterflags]"
	c.help = `List matching messages in the delivery queue.

Prints the message with its ID, last and next delivery attempts, last error.
`
	var f queue.Filter
	flagFilter(c.flag, &f)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueList(xctl(), f)
}

func xctlwritequeuefilter(ctl *ctl, f queue.Filter) {
	fbuf, err := json.Marshal(f)
	xcheckf(err, "marshal filter")
	ctl.xwrite(string(fbuf))
}

func ctlcmdQueueList(ctl *ctl, f queue.Filter) {
	ctl.xwrite("queuelist")
	xctlwritequeuefilter(ctl, f)
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
	flagFilter(c.flag, &f)
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
	flagFilter(c.flag, &f)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueHoldSet(xctl(), f, false)
}

func ctlcmdQueueHoldSet(ctl *ctl, f queue.Filter, hold bool) {
	ctl.xwrite("queueholdset")
	xctlwritequeuefilter(ctl, f)
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
	c.params = "[filterflags] duration"
	c.help = `Change next delivery attempt for matching messages.

The next delivery attempt is adjusted by the duration parameter. If the -now
flag is set, the new delivery attempt is set to the duration added to the
current time, instead of added to the current scheduled time.

Schedule immediate delivery with "mox queue schedule -now 0".
`
	var fromNow bool
	c.flag.BoolVar(&fromNow, "now", false, "schedule for duration relative to current time instead of relative to current next delivery attempt for messages")
	var f queue.Filter
	flagFilter(c.flag, &f)
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
	xctlwritequeuefilter(ctl, f)
	if fromNow {
		ctl.xwrite("yes")
	} else {
		ctl.xwrite("")
	}
	ctl.xwrite(d.String())
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages rescheduled\n", ctl.xread())
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
	flagFilter(c.flag, &f)
	args := c.Parse()
	if len(args) != 1 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueTransport(xctl(), f, args[0])
}

func ctlcmdQueueTransport(ctl *ctl, f queue.Filter, transport string) {
	ctl.xwrite("queuetransport")
	xctlwritequeuefilter(ctl, f)
	ctl.xwrite(transport)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages changed\n", ctl.xread())
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
	flagFilter(c.flag, &f)
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
	xctlwritequeuefilter(ctl, f)
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
		fmt.Printf("%s messages changed\n", ctl.xread())
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
	flagFilter(c.flag, &f)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueFail(xctl(), f)
}

func ctlcmdQueueFail(ctl *ctl, f queue.Filter) {
	ctl.xwrite("queuefail")
	xctlwritequeuefilter(ctl, f)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages marked as failed\n", ctl.xread())
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
	flagFilter(c.flag, &f)
	if len(c.Parse()) != 0 {
		c.Usage()
	}
	mustLoadConfig()
	ctlcmdQueueDrop(xctl(), f)
}

func ctlcmdQueueDrop(ctl *ctl, f queue.Filter) {
	ctl.xwrite("queuedrop")
	xctlwritequeuefilter(ctl, f)
	line := ctl.xread()
	if line == "ok" {
		fmt.Printf("%s messages dropped\n", ctl.xread())
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
