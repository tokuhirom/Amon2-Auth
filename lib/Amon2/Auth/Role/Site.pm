use strict;
use warnings;
use utf8;

package Amon2::Auth::Role::Site;
use Mouse::Role;

requires qw(auth_uri callback);

1;
