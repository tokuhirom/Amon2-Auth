use strict;
use warnings;
use utf8;

package Amon2::Plugin::Auth::Site::Github;

use LWP::UserAgent;
use JSON;
our $VERSION = '0.01';

my $ua = LWP::UserAgent->new(agent => "Amon2::Plugin::OAuth::Client/$VERSION");

our $AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
our $ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token';

sub authenticate {
    my ($class, $c, $conf) = @_;
	$conf->{client_id} || die "Missing Auth.github.client_id";

	my $redirect_uri = URI->new($AUTHORIZE_URL);
	$redirect_uri->query_form(
		map { ($_ => $conf->{$_}) } grep { exists $conf->{$_} } qw(client_id redirect_url scope)
    );
	return $c->redirect($redirect_uri);
}

sub callback {
    my ($class, $c, $conf, $code_conf) = @_;

    my $code = $c->req->param('code') or die "Cannot get a 'code' parameter";
    my $uri = $ACCESS_TOKEN_URL;
    my %params = (code => $code);
    $params{client_id} = $conf->{client_id} || die "Missing github.client_id in configuration";
    $params{client_secret} = $conf->{client_secret} || die "Missing github.client_secret in configuration";
    $params{redirect_url} = $conf->{redirect_url} if exists $conf->{redirect_url};
    my $res = $ua->post($ACCESS_TOKEN_URL, \%params);
    $res->is_success or die "Cannot authenticate";
    my $dat = parse_content($res->decoded_content);
	if (my $err = $dat->{error}) {
		return $code_conf->{on_error}->($c, 'Github', $err);
	}
    my $access_token = $dat->{access_token} or die "Cannot get a access_token";
	return $code_conf->{on_finished}->(
		$c, 'github', $access_token
	);
}

# taken from OAuth::Lite2::Util
use Hash::MultiValue;
use URI::Escape qw(uri_unescape);
sub parse_content {
    my $content = shift;
    my $params  = Hash::MultiValue->new;
    for my $pair ( split /\&/, $content ) {
        my ( $key, $value ) = split /\=/, $pair;
        $key   = uri_unescape( $key   || '' );
        $value = uri_unescape( $value || '' );
        $params->add( $key, $value );
    }
    return $params;
}

1;
