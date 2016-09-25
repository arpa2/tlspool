Project Goals of the TLS Pool
=============================

>   *The TLS Pool responds to many problems in today's world of security for
>   applications. This section details what improvements may be expected.*

An important motivation for the TLS Pool is to separate applications from
security. Applications tend to focus on the functionality of their applications,
and security tends to get in the way. This is due to the different mind sets of
application developers and security experts. It is possible to have the best of
both worlds by splitting the two coding efforts into different processes, and
leave it to the operating system to keep them separate. All communication
between the two mind sets now needs to happen over well-defined local protocols.

In terms of security, what this brings is the certainty that an application
cannot contain unintended bypasses to such sensitive details as private keys or
passwords. Without the separation, it might happen that a rogue plugin or a
faulty JavaScript implementation leads the way from an adverse advertisement to
secrets.

In terms of functionality, this saves a lot of work to the application
programmer; he can now assume that the TLS Pool will be installed, and any
security setup done in there. So no juggling with certificates or keys, no users
complaining about a missing form of authentication, and most importantly, no
needs to update code in a hurry when a hard-to-understand form of attack is
published.

To take the idea of separation of concerns even further, the TLS Pool does not
even get direct access to secret and private keys; it employs PKCS \#11 for
that.  The result is not just that protocols can be kept separate from sensitive
keys, but also that a great variety of key storage solutions is available; there
are many implementations of PKCS \#11, each with their own security premises,
and the TLS Pool can be configured on top of each of them.  If your security
policy requires the concealment of keys in a piece of hardware, then this is how
you do it.

An interesting extra option that the use of PKCS \#11 brings is that some
solutions work over a network.  This might be used to separately roll keys and
certificates, which can be a great help with end-user rollouts of certificate
hierarchies.  In terms of our
[IdentityHub](http://arpa2.readthedocs.io/en/latest/phases/2-identityhub.html)
plans, we intend to standardise remote PKCS \#11 and support web-based
management of identities, certificates and keys.

Another explicit goal of the TLS Pool is centralisation of security.  This may
sound like it introduces a “single point of attack”, but in reality this is not
different from everyday practice: there are hardly any applications with a
switchable security backend.  Having a central node for all things TLS means
that it is possible to quickly replace a problematic TLS implementation with a
new one.  In current deployments, work may have to be done on a lot of
individual application; and each will have its own style of configuring TLS, so
that can be very frustrating — especially when in a hurry.

The TLS Pool can easily be configured by automatic software, so as to support
provisioning of security settings.  When a problem with TLS occurs, a quick
change by an operator may lead to immediate changes to many independent
installations.  This is of course a choice to be made; it is equally possible to
administer the TLS Pool by hand, but even then the advantage remains that it is
one setting that applies to all programs that deploy the TLS Pool and that the
changes are consistent for all TLS Pool setups.

Finally, the TLS Pool aims at being [innovative](innov.html) where cryptography
is concerned.  The intention is to have as many facilities ready for use, and to
leave it to administration to make a selection.  An individual TLS
implementation in one application is not helpful in raising the bar in a
security policy, but having a common ground with many facilities available to
all means that it is possible to actually pitch for a higher level of security
in policies and in practice.
