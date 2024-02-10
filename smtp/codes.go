package smtp

// ../rfc/5321:2863

// Reply codes.
var (
	C211SystemStatus = 211
	C214Help         = 214
	C220ServiceReady = 220
	C221Closing      = 221
	C235AuthSuccess  = 235 // ../rfc/4954:573

	C250Completed               = 250
	C251UserNotLocalWillForward = 251
	C252WithoutVrfy             = 252

	C334ContinueAuth = 334 // ../rfc/4954:187
	C354Continue     = 354

	C421ServiceUnavail         = 421
	C432PasswdTransitionNeeded = 432 // ../rfc/4954:578
	C454TempAuthFail           = 454 // ../rfc/4954:586
	C450MailboxUnavail         = 450
	C451LocalErr               = 451
	C452StorageFull            = 452 // Also for "too many recipients", ../rfc/5321:3576
	C455BadParams              = 455

	C500BadSyntax              = 500
	C501BadParamSyntax         = 501
	C502CmdNotImpl             = 502
	C503BadCmdSeq              = 503
	C504ParamNotImpl           = 504
	C521HostNoMail             = 521 // ../rfc/7504:179
	C530SecurityRequired       = 530 // ../rfc/3207:148 ../rfc/4954:623
	C534AuthMechWeak           = 534 // ../rfc/4954:593
	C535AuthBadCreds           = 535 // ../rfc/4954:600
	C538EncReqForAuth          = 538 // ../rfc/4954:630
	C550MailboxUnavail         = 550
	C551UserNotLocal           = 551
	C552MailboxFull            = 552
	C553BadMailbox             = 553
	C554TransactionFailed      = 554
	C555UnrecognizedAddrParams = 555
	C556DomainNoMail           = 556 // ../rfc/7504:207
)

// Short enhanced reply codes, without leading number and first dot.
//
// See https://www.iana.org/assignments/smtp-enhanced-status-codes/smtp-enhanced-status-codes.xhtml
var (
	// 0.x - Other or Undefined Status.
	// ../rfc/3463:287
	SeOther00 = "0.0"

	// 1.x - Address.
	// ../rfc/3463:295
	SeAddr1Other0                  = "1.0"
	SeAddr1UnknownDestMailbox1     = "1.1"
	SeAddr1UnknownSystem2          = "1.2"
	SeAddr1MailboxSyntax3          = "1.3"
	SeAddr1MailboxAmbiguous4       = "1.4"
	SeAddr1DestValid5              = "1.5" // For success responses.
	SeAddr1DestMailboxMoved6       = "1.6"
	SeAddr1SenderSyntax7           = "1.7"
	SeAddr1BadSenderSystemAddress8 = "1.8"
	SeAddr1NullMX                  = "1.10" // ../rfc/7505:237

	// 2.x - Mailbox.
	// ../rfc/3463:361
	SeMailbox2Other0             = "2.0"
	SeMailbox2Disabled1          = "2.1"
	SeMailbox2Full2              = "2.2"
	SeMailbox2MsgLimitExceeded3  = "2.3"
	SeMailbox2MailListExpansion4 = "2.4"

	// 3.x - Mail system.
	// ../rfc/3463:405
	SeSys3Other0            = "3.0"
	SeSys3StorageFull1      = "3.1"
	SeSys3NotAccepting2     = "3.2"
	SeSys3NotSupported3     = "3.3"
	SeSys3MsgLimitExceeded4 = "3.4"
	SeSys3Misconfigured5    = "3.5"

	// 4.x - Network and routing.
	// ../rfc/3463:455
	SeNet4Other0           = "4.0"
	SeNet4NoAnswer1        = "4.1"
	SeNet4BadConn2         = "4.2"
	SeNet4Name3            = "4.3"
	SeNet4Routing4         = "4.4"
	SeNet4Congestion5      = "4.5"
	SeNet4Loop6            = "4.6"
	SeNet4DeliveryExpired7 = "4.7"

	// 5.x - Mail delivery protocol.
	// ../rfc/3463:527
	SeProto5Other0              = "5.0"
	SeProto5BadCmdOrSeq1        = "5.1"
	SeProto5Syntax2             = "5.2"
	SeProto5TooManyRcpts3       = "5.3"
	SeProto5BadParams4          = "5.4"
	SeProto5ProtocolMismatch5   = "5.5"
	SeProto5AuthExchangeTooLong = "5.6" // ../rfc/4954:650

	// 6.x - Message content/media.
	// ../rfc/3463:579
	SeMsg6Other0                    = "6.0"
	SeMsg6MediaUnsupported1         = "6.1"
	SeMsg6ConversionProhibited2     = "6.2"
	SeMsg6ConversoinUnsupported3    = "6.3"
	SeMsg6ConversionWithLoss4       = "6.4"
	SeMsg6ConversionFailed5         = "6.5"
	SeMsg6NonASCIIAddrNotPermitted7 = "6.7" // ../rfc/6531:735
	SeMsg6UTF8ReplyRequired8        = "6.8" // ../rfc/6531:746
	SeMsg6UTF8CannotTransfer9       = "6.9" // ../rfc/6531:758

	// 7.x - Security/policy.
	// ../rfc/3463:628
	SePol7Other0                = "7.0"
	SePol7DeliveryUnauth1       = "7.1"
	SePol7ExpnProhibited2       = "7.2"
	SePol7ConversionImpossible3 = "7.3"
	SePol7Unsupported4          = "7.4"
	SePol7CryptoFailure5        = "7.5"
	SePol7CryptoUnsupported6    = "7.6"
	SePol7MsgIntegrity7         = "7.7"
	SePol7AuthBadCreds8         = "7.8"  // ../rfc/4954:600
	SePol7AuthWeakMech9         = "7.9"  // ../rfc/4954:593
	SePol7EncNeeded10           = "7.10" // ../rfc/5248:359
	SePol7EncReqForAuth11       = "7.11" // ../rfc/4954:630
	SePol7PasswdTransitionReq12 = "7.12" // ../rfc/4954:578
	SePol7AccountDisabled13     = "7.13" // ../rfc/5248:399
	SePol7TrustReq14            = "7.14" // ../rfc/5248:418
	// todo spec: duplicate spec of 7.16 ../rfc/4865:412 ../rfc/6710:878
	// todo spec: duplicate spec of 7.17 ../rfc/4865:418 ../rfc/7293:1137
	SePol7NoDKIMPass20        = "7.20" // ../rfc/7372:137
	SePol7NoDKIMAccept21      = "7.21" // ../rfc/7372:148
	SePol7NoDKIMAuthorMatch22 = "7.22" // ../rfc/7372:175
	SePol7SPFResultFail23     = "7.23" // ../rfc/7372:192
	SePol7SPFError24          = "7.24" // ../rfc/7372:204
	SePol7RevDNSFail25        = "7.25" // ../rfc/7372:233
	SePol7MultiAuthFails26    = "7.26" // ../rfc/7372:246
	SePol7SenderHasNullMX27   = "7.27" // ../rfc/7505:246
	SePol7ARCFail             = "7.29" // ../rfc/8617:1438
	SePol7MissingReqTLS       = "7.30" // ../rfc/8689:448
)
