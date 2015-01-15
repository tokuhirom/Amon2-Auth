use strict;
use warnings;
use utf8;

package Amon2::Auth::Site::Loctouch;
use Mouse;

use Amon2::Auth;
use LWP::UserAgent;
use JSON;
use Amon2::Auth::Util qw(parse_content);
our $VERSION = '0.06';

sub moniker { 'loctouch' }

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

has user_info => (
    is => 'rw',
    isa => 'Bool',
    default => 1,
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
	default => 'https://tou.ch/oauth2/authenticate',
);
has access_token_url => (
	is => 'ro',
	isa => 'Str',
	default => 'https://tou.ch/oauth2/token',
);
has redirect_uri => (
	is => 'ro',
	isa => 'Str',
	required => 1,
);

sub auth_uri {
    my ($self, $c, $callback_uri) = @_;
	$callback_uri or die "Missing mandatory parameter: callback_uri";
	if ($self->redirect_uri ne $callback_uri) {
		die "redirect uri missmatch: " . join(', ', $self->redirect_uri, $callback_uri);
	}

	my $redirect_uri = URI->new($self->authorize_url);
	my %params;
	$params{redirect_uri} = $self->redirect_uri;
	$params{response_type} = 'code';
	for (qw(client_id)) {
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
	# grant_type=authorization_code&client_id=CLIENT_ID&client_secret=CLIENT_SECRET&code=CODE&redirect_uri=REDIRECT_URI
	$params{grant_type} = 'authorization_code';
    $params{client_id} = $self->client_id;
    $params{client_secret} = $self->client_secret;
    $params{redirect_uri} = $self->redirect_uri;
    my $res = $self->ua->post($self->access_token_url, \%params);
    $res->is_success or die "Cannot authenticate: " . $res->content;
    my $dat = decode_json($res->decoded_content);
	if (my $err = $dat->{error}) {
		return $callback->{on_error}->($err);
	}
    my $access_token = $dat->{access_token} or die "Cannot get a access_token";
    my @args = ($access_token);
    if ($self->user_info) {
        my $res = $self->ua->get("https://api.loctouch.com/v1/users/\@self?oauth_token=${access_token}");
        $res->is_success or return $callback->{on_error}->($res->status_line);
        my $dat = decode_json($res->decoded_content);
        push @args, $dat->{user};
    }
	return $callback->{on_finished}->( @args );
}

1;
__END__

=head1 NAME

Amon2::Auth::Site::Loctouch - Loctouch integration for Amon2

=head1 SYNOPSIS


    __PACKAGE__->load_plugin('Web::Auth', {
        module => 'Loctouch',
        on_finished => sub {
            my ($c, $token, $user) = @_;
            my $name = $user->{name} || die;
            $c->session->set('name' => $name);
            $c->session->set('site' => 'loctouch');
            return $c->redirect('/');
        }
    });

=head1 DESCRIPTION

This is a loctouch authentication module for Amon2. You can call a loctouch APIs with this module.

=head1 ATTRIBUTES

=over 4

=item client_id

=item client_secret

=item redirect_uri(Required)

=item user_info(Default: true)

Fetch user information after authenticate?

=item ua(instance of LWP::UserAgent)

You can replace instance of L<LWP::UserAgent>.

=back

=head1 METHODS

=over 4

=item C<< $auth->auth_uri($c:Amon2::Web, $callback_uri : Str) :Str >>

Get a authenticate URI.

=item C<< $auth->callback($c:Amon2::Web, $callback:HashRef) : Plack::Response >>

Process the authentication callback dispatching.

C<< $callback >> MUST have two keys.

=over 4

=item on_error

on_error callback function is called if an error was occurred.

The arguments are following:

    sub {
        my ($c, $error_message) = @_;
        ...
    }

=item on_finished

on_finished callback function is called if an authentication was finished.

The arguments are following:

    sub {
        my ($c, $access_token, $user) = @_;
        ...
    }

C<< $user >> contains user information. This code contains a information like L<https://api.loctouch.com/users/dankogai>.

If you set C<< $auth->user_info >> as false value, authentication engine does not pass C<< $user >>.

=back

=back

