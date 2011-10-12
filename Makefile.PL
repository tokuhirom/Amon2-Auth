use inc::Module::Install;
use Module::Install::AuthorTests;

name 'Amon2-Plugin-Auth';
all_from 'lib/Amon2/Plugin/Auth.pm';

requires 'Amon2' => '3.03';
requires 'Plack' =>  0.9949;
requires 'LWP' => '6.00';
requires 'LWP::Protocol::https' => '6.00';
requires 'JSON' => 2;

requires 'Class::Method::Modifiers';

# for Github
requires 'Hash::MultiValue';
requires 'URI::Escape';

# for Twitter
requires 'Net::Twitter::Lite' => '0.10004';

tests 't/*.t t/*/*.t t/*/*/*.t t/*/*/*/*.t';
test_requires 'Test::More' => 0.96; # done_testing, subtest
# test_requires 'Test::Requires';
author_tests('xt');
WriteAll;
