---
layout: post
title: Revisiting Telegram's Security Protocol (MTProto)
date: 2022-12-10
---

Telegram has some issues. It is not my preferred messaging app.

From personal experience, most Telegram users just want an alternative to platforms like Facebook's Messenger or iMessage. But, also anecdotally, most of its users don't understand the fundamentals behind its encryption or potential to preserve data confidentiality or integrity.

Meaning: If you're a Telegram user, you should research MTProto.

A little over a year ago, I wrote a paper about Telegram as a whole. The paper was meant to illustrate some security concerns and considerations with the application as a whole, server and clients alike. The findings were largely focused on MTProto2, but it covered a wide breadth of concerns in the application.

For the record, Telegram has fixed some of the vulnerabilities outlined in that paper. However, the application still defaults to SMS authentication only (which can be defeated by SIM-swapping, where someone calls your phone ISP, requests that your phone number be transferred to their device, and can recieve your SMS messages and SMS codes). It also reveals your phone number by default. Also, you *must* register a phone number to use the service.

This follow-up is going to forego those caveats. If you have concerns, you can just try the app or ask a friend. Instead, this discussion will focus only on the encryption protocol.

In general, MTProto and MTProto2 have faced a lot of backlash from security researchers. Here are some timeless reasons why:

-   The protocol is homegrown. Homemade protocols are generally not recommended unless they have undergone extensive security testing.
-   The protocol is based on other encryption protocols, like hashing and asymmetric encryption, as its "building blocks." This reduces the protocol's security to the security of these building blocks.
-   The protocol only enforces end-to-end encryption for "secret chats." Not only are these not the default, but they are also not available for group chats.
-   For non-secret chats, message encryption is undermined in the server. In transit, the message is encrypted and sent to the servers. There, it is decrypted in plaintext, and re-encrypted with the database's key. (That process reverses when the message is sent to the recipient.) The idea that it is decrpyted at all in the server undermines the protections offered by encryption in the first place. 

None of these reasons have really changed over time. Secret chats are new, but they are very limited in capabilities compared to regular (non-end-to-end encrypted) and group chats. 

The notion that the protocol itself allows messages to be decrypted in the server is, and always has been, pause for concern. This places undue trust on the server, which is closed-source. You never really know what happens on its servers. 

Albrecht et al. observe that MTProto will protect the integrity of plaintext data, but does nothing to protect the integrity of ciphertext (encrypted data). This implies that the protocol will always need to decrypt the data before it can determine if anything was tampered. This is considered less reliable than schemes that protect the ciphertext integrity. (It doesn't make sense to me why you would protect the plaintext instead of the ciphertext because valid ciphertext will decrypt to valid plaintext anyway.) 

They also observe that client-side security can find itself at risk if a third-party Telegram client is not performing robust security testing on their custom client. This makes the security of any third-party Telegram client ambiguous. 

My biggest issue with Telegram is that it's advertised in a way that does not match its implementation. Many users expect that it preserves privacy and security for all chats. Their exepctation better reflects how secret chats work; and this, as noted, is not true of default or group chats. 

If Telegram ever wanted to sell user data or metadata, they have every opportunity because the plaintext messages are right there in their servers. The organization says takes a stance in favor of user privacy. So, now you're left trusting the company.

People often compare Telegram to Signal with respect to its security. I argue that there is no comparison because Signal will end-to-end encrypt every chat, including group chats.

Telegram often gets attention because it has more features than Signal. However, the Telegram's "secret chats" lack many features that are available to its own default and group chats. In fact, secret chats in Telegram look a lot like, well, every chat in Telegram&mdash;except, of course, Telegram's secret chats have limited features comapred to any chat type in Signal.

People will certainly continue to use platforms like Telegram. If you like Telegram, you should use it. Just use it with a better understanding of *what* you are using: what it is and, as important, is *not* doing. 

# References

https://mtpsym.github.io/

https://core.telegram.org/api/end-to-end

https://www.wired.com/story/telegram-encryption-whatsapp-settings

https://www.kaspersky.com/blog/telegram-privacy-security/38444/

https://medium.com/@justinomora/demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-ad6a567e6cb4

