use strict;
use warnings;
use utf8;

package Amon2::Auth::Site::Github;
use Mouse;

use Amon2::Auth;
use LWP::UserAgent;
use JSON;
use Amon2::Auth::Util qw(parse_content);
our $VERSION = '0.01';

sub moniker { 'github' }

has client_id => (
	is => 'ro',
	isa => 'Str',
	required => 1,
);
has client_secret => (
	is => 'ro',
	isa => 'Str',
	required => 1,
);
has scope => (
	is => 'ro',
	isa => 'Str',
);

has ua => (
	is => 'ro',
	isa => 'LWP::UserAgent',
	lazy => 1,
	default => sub {
		my $ua = LWP::UserAgent->new(agent => "Amon2::Auth/$Amon2::Auth::VERSION");
	},
);

has authorize_url => (
	is => 'ro',
	isa => 'Str',
	default => 'https://github.com/login/oauth/authorize',
);
has access_token_url => (
	is => 'ro',
	isa => 'Str',
	default => 'https://github.com/login/oauth/access_token',
);
has redirect_url => (
	is => 'ro',
	isa => 'Str',
);

sub auth_uri {
    my ($self, $c, $callback_uri) = @_;

	my $redirect_uri = URI->new($self->authorize_url);
	my %params;
	if (defined $callback_uri) {
		$params{redirect_uri} = $callback_uri;
	} elsif (defined $self->redirect_url) {
		$params{redirect_uri} = $self->redirect_url;
	}
	for (qw(client_id scope)) {
		next unless defined $self->$_;
		$params{$_} = $self->$_;
	}
	$redirect_uri->query_form(%params);
	return $redirect_uri->as_string;
}

sub callback {
    my ($self, $c, $callback) = @_;

    my $code = $c->req->param('code') or die "Cannot get a 'code' parameter";
    my %params = (code => $code);
    $params{client_id} = $self->client_id;
    $params{client_secret} = $self->client_secret;
    $params{redirect_url} = $self->redirect_url if defined $self->redirect_url;
    my $res = $self->ua->post($self->access_token_url, \%params);
    $res->is_success or die "Cannot authenticate";
    my $dat = parse_content($res->decoded_content);
	if (my $err = $dat->{error}) {
		return $callback->{on_error}->($err);
	}
    my $access_token = $dat->{access_token} or die "Cannot get a access_token";
	return $callback->{on_finished}->( $access_token );
}

1;
