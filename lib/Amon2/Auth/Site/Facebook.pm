use strict;
use warnings;
use utf8;

package Amon2::Auth::Site::Facebook;
use Mouse;
use LWP::UserAgent;
use URI;
use JSON;
use Amon2::Auth::Util qw(parse_content);
use Amon2::Auth;

sub moniker { 'facebook' }

for (qw(client_id scope client_secret)) {
	has $_ => (
		is => 'ro',
		isa => 'Str',
		required => 1,
	);
}

has ua => (
	is => 'ro',
	isa => 'LWP::UserAgent',
	lazy => 1,
	default => sub {
		my $ua = LWP::UserAgent->new(agent => "Amon2::Auth/$Amon2::Auth::VERSION");
	},
);

sub auth_uri {
	my ($self, $c, $callback_uri) = @_;
	$callback_uri or die "Missing mandatory parameter: callback_uri";

	my $url = URI->new('https://www.facebook.com/dialog/oauth');
	my %params;
	for (qw(client_id scope)) {
		$params{$_} = $self->$_;
	}
	$params{redirect_uri} = $callback_uri;
	$url->query_form(%params);
	return $url->as_string;
}

sub callback {
	my ($self, $c, $callback) = @_;
	if (my $error_description = $c->req->param('error_description')) {
		return $callback->{on_error}->($error_description);
	}

	my $uri = URI->new('https://graph.facebook.com/oauth/access_token');
	my %params;
	for (qw(client_id client_secret)) {
		$params{$_} = $self->$_;
	}
	$params{redirect_uri} = $c->req->uri->as_string;
	$params{redirect_uri} =~ s/\?.+//;
	$params{code} = $c->req->param('code') or die;
	$uri->query_form(%params);
	my $res = $self->ua->get($uri->as_string);
	$res->is_success or do {
		warn $res->decoded_content;
		return $callback->{on_error}->($res->decoded_content);
	};
    my $dat = parse_content($res->decoded_content);
	if (my $err = $dat->{error}) {
		return $callback->{on_error}->($err);
	}
    my $access_token = $dat->{access_token} or die "Cannot get a access_token";
	return $callback->{on_finished}->($access_token);
}

1;

