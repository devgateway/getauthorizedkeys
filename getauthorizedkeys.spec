# Copyright 2016-2018 Development Gateway, Inc
# This file is part of getauthorizedkeys, see COPYING
%define esc_sha  5795e78c34b7720aee938806c3606defcb0711de
%define inih_sha 0ee2bf26abccc63ee0a5a416ed9cdf4d113d8c25

Name:           getauthorizedkeys
Version:        0.3
Release:        %{rel}%{!?rel:1}
License:        GPLv3
Vendor:         Development Gateway
Summary:        Get SSH public keys from LDAP
Source:         https://github.com/devgateway/%{name}/archive/v%{version}.tar.gz
Source1:        https://github.com/benhoyt/inih/archive/%{inih_sha}.tar.gz
Source2:        https://github.com/devgateway/ldapescape/archive/%{esc_sha}.tar.gz
BuildRequires:  cmake >= 2.8.11

%description
This helper utility looks up the user's SSH public keys in LDAP, and prints
them to stdout. It's designed for use with AuthorizedKeysCommand
option of sshd.

%prep
%setup
gzip -dc "%SOURCE1" | tar -C inih -xvvf - --strip-components=1
gzip -dc "%SOURCE2" | tar -C ldapescape -xvvf - --strip-components=1

%build
cmake \
	-DCONFIGFILE:FILE=%{_sysconfdir}/getauthorizedkeys.ini \
	-DLIBEXEC=%_libexecdir \
	-DMANDIR=%_mandir \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	.
make

%install
make DESTDIR=%buildroot install
mkdir -p %buildroot%_sysconfdir
install -m 0660 getauthorizedkeys.ini %buildroot%_sysconfdir/

%files
%_libexecdir/*
%_mandir/man*/*
%config %attr(0660,-,-) %_sysconfdir/getauthorizedkeys.ini
%doc COPYING

%clean
rm -rf %_buildrootdir
