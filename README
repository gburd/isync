 _                      
(_)___ _   _ _ __   ___ 
| / __| | | | '_ \ / __|
| \__ \ |_| | | | | (__ 
|_|___/\__, |_| |_|\___|
       |___/            
isync/mbsync - free (GPL) mailbox synchronization program
http://isync.sf.net/

See AUTHORS for contact information.

``mbsync'' is a command line application which synchronizes mailboxes;
currently Maildir and IMAP4 mailboxes are supported. New messages, message
deletions and flag changes can be propagated both ways.
``mbsync'' is suitable for use in IMAP-disconnected mode.

Synchronization is based on unique message identifiers (UIDs), so no
identification conflicts can occur (as opposed to some other mail
synchronizers).
Synchronization state is kept in one local text file per mailbox pair;
multiple replicas of a mailbox can be maintained.

isync is the project name, while mbsync is the current executable name; this
change was necessary because of massive changes in the user interface. An
isync executable still exists; it is a compatibility wrapper around mbsync.

* Features

    * Fine-grained selection of synchronization operations to perform
    * Synchronizes single mailboxes or entire mailbox collections
    * Partial mirrors possible: keep only the latest messages locally
    * Trash functionality: backup messages before removing them
    * IMAP features:
	* Supports TLS/SSL via imaps: (port 993) and STARTTLS (RFC2595)
	* Supports CRAM-MD5 (RFC2195) for authentication
	* Supports NAMESPACE (RFC2342) for simplified configuration
	* Pipelining for maximum speed

* Compatibility

    isync should work fairly well with any IMAP4 compliant server;
    particularily efficient with those that support the UIDPLUS and LITERAL+
    extensions.

    Courier 1.4.3 is known to be buggy, version 1.7.3 works fine.

    c-client (UW-IMAP, Pine) is mostly fine, but versions less than 2004a.352
    tend to change UIDVALIDITY pretty often when used with unix/mbox mailboxes,
    making isync refuse synchronization.
    The "cure" is to simply copy the new UIDVALIDITY from the affected
    mailbox to mbsync's state file. This is a Bad Hack (TM), but it works -
    use at your own risk (if the UIDVALIDITY change was genuine, this will
    delete all messages in the affected mailbox - not that this ever
    happened to me).

* Platforms

    At some point, ``isync'' has successfully run on:
    Linux, Solaris 2.7, OpenBSD 2.8, FreeBSD 4.3.

    Note that Cygwin cannot be reasonably supported due to restrictions
    of the Windows file system.

* Requirements

    Berkley DB 4.2+
    OpenSSL for TLS/SSL support (optional)

* Installation

    ./configure
    make install

* Help

    Please see the man page for complete documentation.
