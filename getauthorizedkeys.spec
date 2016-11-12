# Copyright 2016 Development Gateway, Inc
# This file is part of pam_param, see COPYING
%define esc_sha  ed4d4e107cc2279858818005b684f4f1b17e86d6
%define inih_sha 18a67c516358e2791ab720a1abe411d991774f3e

Name:           getauthorizedkeys
Version:        0.1
Release:        %{rel}%{!?rel:1}
License:        GPLv3
Vendor:         Development Gateway
Summary:        Get SSH public keys from LDAP
Source:         %name.zip
Source1:        https://github.com/benhoyt/inih/archive/%{inih_sha}.zip
Source2:        https://github.com/devgateway/ldapescape/archive/%{esc_sha}.zip
BuildRequires:  cmake >= 2.8.11

%description
This helper utility looks up the user's SSH public keys in LDAP, and prints
them to stdout. It's designed for use with AuthorizedKeysCommand
option of sshd.

%prep
%setup -n %name
%setup -D -T -a 1 -n %name
%setup -D -T -a 2 -n %name

%build
cmake \
	-DCONFIGFILE:FILE=%{_sysconfdir}/getauthorizedkeys.ini \
	-DLIBEXEC=%_libexecdir \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	.
make

%install
make DESTDIR=%buildroot install
mkdir -p %buildroot%_sysconfdir
install -m 0660 getauthorizedkeys.ini %buildroot%_sysconfdir/

%files
%{_moduledir}/*
%_mandir/man*/*
%config %attr(0660,-,-) %_sysconfdir/getauthorizedkeys.ini
%doc COPYING

%clean
rm -rf %_buildrootdir
