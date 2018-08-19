===================================
Google Authenticator (PAM) wrappers
===================================

Ⓒ 2018 Michał Górny

Licensed under the terms of 2-clause BSD license


Introduction
============
This package provides a few wrappers for the purpose of using Google
Authenticator PAM modules [#GAUTH]_ for two-step SSH authentication
securely.  It is specifically focused on the use in Gentoo
Infrastructure [#GENTOO-2FA]_ but can be used on any multi-user system.
It satisfies the following goals:

1. HOTP/TOTP is used as second step, combined with SSH pubkey
   authentication.

2. Two-step authentication is entirely optional.  Users who did
   not enable it use regular pubkey-only authentication.

3. Secrets (and emergency scratch codes) are not readable to user,
   and can only be modified (and second step can only be disabled)
   after password authentication.


Problems with google-authenticator-libpam
=========================================
The standard configuration of google-authenticator-libpam relies
on storing secrets in user's home directories.  While this is convenient
to users, it raises security-related concerns.  For example, if
an attacker manages to temporarily gain access to the user's session
or the filesystem, he can easily read the secrets and duplicate
the token source without leaving much of a trace that the system
has been compromised.

For comparison, shadow passwords are not readable to the user (even
though they are normally hashed).  The user also can't change his
password without typing the old password first.  SSH authorized_keys
are usually not protected but we still can assume that the attacker
would not have enough resources to recreate the private key material
from the public key.

This problem could be solved via storing keys separately, and making
them unreadable to user.  However, this implies that either the sysadmin
needs to manually update user's secrets or there needs to be additional
automation doing that.  Those wrappers aim to be the latter.


Installation
============
This package includes a standard CMake-based build system with
GNUInstallDirs support.  The following additional configuration
variables are provided:

CMAKE_INSTALL_PAMDIR
  Directory where pam.d files should be installed (``/etc/pam.d``).

CMAKE_INSTALL_GAUTH_STATEDIR
  Directory where user secrets will be stored (``/var/lib/gauth``).

GAUTH_USERNAME
  User used to manage secrets (``root``).

Please note that the ``install`` target does not take care of changing
file ownerships or modifying configuration of live services.  You need
to update your ``/etc/pam.d/ssh`` and OpenSSH or similar setup manually.

You also need to make sure that ``gauthctl`` and ``gauth-test`` are both
owned by ``GAUTH_USERNAME`` and setuid.  The statedir needs to also
be owned by ``GAUTH_USERNAME``, and kept unreadable to other users.


Usage
=====
The following executables are intended for user's direct use:

disable-2fa
  Disables second step authentication for the current user.

enable-2fa-custom
  Enables second step authentication with full google-authenticator
  prompt set.

enable-2fa-totp
  Enables second step authentication with Gentoo TOTP defaults.

gauth-test
  Performs a test second step authentication.  Used to verify that
  the current setup is working correctly.


Implementation details
======================
The three wrapper scripts use ``gauthctl`` to update the user secrets.
This tool takes a single option, ``--enable`` or ``--disable``
appropriately, performs PAM authentication (using standard system
mechanism, i.e. the regular user password) and updates the secret.

The ``--enable`` option reads new configuration from fd 3, and writes
it to the isolated secret directory after successful PAM authentication.
The ``--disable`` option simply removes the secret, effectively
disabling the second step authentication.


References
==========
.. [#GAUTH] Google Authenticator PAM module
   (https://github.com/google/google-authenticator-libpam)

.. [#GENTOO-2FA] dev.gentoo.org 2-step authentication
   (https://wiki.gentoo.org/wiki/Project:Infrastructure/dev.gentoo.org_2-step_authentication)
