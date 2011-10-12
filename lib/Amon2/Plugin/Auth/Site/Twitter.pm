use strict;
use warnings;
use utf8;

package Amon2::Plugin::Auth::Site::Twitter;
use Net::Twitter::Lite;

sub _nt {
	my ($class, $c, $conf) = @_;
	my $consumer_key = $conf->{consumer_key} or die "Missing Auth.Twitter.consumer_key in configuration";
	my $consumer_secret = $conf->{consumer_secret} or die "Missing Auth.Twitter.consumer_secret in configuration";
	my $nt = Net::Twitter::Lite->new(
		consumer_key => $consumer_key,
		consumer_secret => $consumer_secret,
	);
	return $nt;
}

sub authenticate {
	my ($class, $c, $conf) = @_;


	my $callback = $c->req->uri;
	$callback =~ s!/authenticate$!/callback!;
	warn "CALLBACK: $callback";

	my $nt = $class->_nt($c, $conf);
	my $redirect_uri = $nt->get_authorization_url(callback => $callback);
    $c->session->set(
        auth_twitter => [ $nt->request_token, $nt->request_token_secret, ] );
	return $c->redirect($redirect_uri);
}

sub callback {
	my ($class, $c, $conf, $code_conf) = @_;

	my $cookie = $c->session->get('auth_twitter')
		or return $code_conf->{on_error}->($c, 'Twitter', "Session error");

	my $nt = $class->_nt($c, $conf);
	$nt->request_token($cookie->[0]);
	$nt->request_token_secret($cookie->[1]);
	my $verifier = $c->req->param('oauth_verifier');
	my ($access_token, $access_token_secret, $user_id, $screen_name) =
		$nt->request_access_token(verifier => $verifier);
	return $code_conf->{on_finished}->($c, 'twitter', $access_token, $access_token_secret, $user_id, $screen_name);
}

1;

