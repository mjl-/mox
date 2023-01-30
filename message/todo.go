package message

// todo: we should parse headers ourselves

// Link rfc updates about UTF-8 characters in messages.
// These productions list valid characters in contexts:
// VCHAR, visible printing: ../rfc/5234:774 ../rfc/6532:236
// ctext, in comment: ../rfc/5322:602 ../rfc/6532:238
// atext, in atom: ../rfc/5322:679 ../rfc/6532:240
// qtext, in quoted string: ../rfc/5322:735 ../rfc/6532:242
// text, in message body: ../rfc/5322:1001 ../rfc/6532:244
// dtext, in domain: ../rfc/5322:967 ../rfc/6532:247
