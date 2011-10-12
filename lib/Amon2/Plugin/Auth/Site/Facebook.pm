use strict;
use warnings;
use utf8;

package Amon2::Plugin::Auth::Site::Facebook;
use LWP::UserAgent;
use URI;
use JSON;
use Amon2::Plugin::Auth::Util qw(parse_content);

my $ua = LWP::UserAgent->new();

sub auth_uri {
	my ($class, $c, $conf, $redirect_uri) = @_;
	my $url = URI->new('https://www.facebook.com/dialog/oauth');
	my %params;
	for (qw(client_id scope)) {
		$params{$_} = $conf->{$_} or die "Missing auth.facebook.$_ in your configuration";
	}
	if ($redirect_uri) {
		$params{redirect_uri} = $redirect_uri;
	} else {
		$params{redirect_uri} = $c->req->uri;
		$params{redirect_uri} =~ s/authenticate$/callback/;
	}
	$url->query_form(%params);
	return $url->as_string;
}

sub authenticate {
	my ($class, $c, $conf) = @_;
	my $url = $class->auth_uri($c, $conf);
	return $c->redirect($url);
}

sub callback {
	my ($class, $c, $conf, $code_conf) = @_;
	if (my $error_description = $c->req->param('error_description')) {
		return $code_conf->{on_error}->($c, 'facebook', $error_description);
	}

	my $uri = URI->new('https://graph.facebook.com/oauth/access_token');
	my %params;
	for (qw(client_id client_secret)) {
		$params{$_} = $conf->{$_} or die "Missing auth.facebook.$_ in your configuration";
	}
	$params{redirect_uri} = $c->req->uri->as_string;
	$params{redirect_uri} =~ s/\?.+//;
	$params{code} = $c->req->param('code') or die;
	$uri->query_form(%params);
	warn $uri;
	my $res = $ua->get($uri->as_string);
	$res->is_success or do {
		warn $res->decoded_content;
		return $code_conf->{on_error}->($c, 'facebook', $res->decoded_content);
	};
    my $dat = parse_content($res->decoded_content);
	if (my $err = $dat->{error}) {
		return $code_conf->{on_error}->($c, 'Github', $err);
	}
    my $access_token = $dat->{access_token} or die "Cannot get a access_token";
	return $code_conf->{on_finished}->(
		$c, 'facebook', $access_token
	);
}

1;

