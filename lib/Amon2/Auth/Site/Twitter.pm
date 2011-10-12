use strict;
use warnings;
use utf8;

package Amon2::Auth::Site::Twitter;
use Mouse;
use Net::Twitter::Lite;

has consumer_key => (
	is => 'ro',
	isa => 'Str',
	required => 1,
);
has consumer_secret => (
	is => 'ro',
	isa => 'Str',
	required => 1,
);

sub _nt {
	my ($self) = @_;
    my $nt = Net::Twitter::Lite->new(
        consumer_key    => $self->consumer_key,
        consumer_secret => $self->consumer_secret,
    );
	return $nt;
}

sub auth_uri {
	my ($self, $c, $callback_uri) = @_;

	my $nt = $self->_nt();
	my $redirect_uri = $nt->get_authorization_url(callback => $callback_uri);
    $c->session->set( auth_twitter => [ $nt->request_token, $nt->request_token_secret, ] );
	return $redirect_uri;
}

sub callback {
	my ($self, $c, $callback) = @_;

	my $cookie = $c->session->get('auth_twitter')
		or return $callback->{on_error}->("Session error");

	my $nt = $self->_nt();
	$nt->request_token($cookie->[0]);
	$nt->request_token_secret($cookie->[1]);
	my $verifier = $c->req->param('oauth_verifier');
	my ($access_token, $access_token_secret, $user_id, $screen_name) =
		$nt->request_access_token(verifier => $verifier);
	return $callback->{on_finished}->($access_token, $access_token_secret, $user_id, $screen_name);
}

1;

