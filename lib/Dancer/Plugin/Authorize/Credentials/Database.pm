# ABSTRACT: Dancer::Plugin::Authorize authentication via the Dancer::Plugin::Database!

package Dancer::Plugin::Authorize::Credentials::Database;

use strict;
use warnings;
use base qw/Dancer::Plugin::Authorize::Credentials/;

=head1 SYNOPSIS

    my $options = {
    
        
    
    };

    my $class = "Dancer::Plugin::Authorize::Credentials::Database";
    print 'logged in' if $class->new->authorize($options, 'user01', '****');
    
The Dancer::Plugin::Database settings will be used to connect to the database and query the 
datastore, the user accounts tables, columns, etc should be defined in the configuration file as follows:

    plugins:
      Authorize:
        auth: # keyword allows one to setup multiple authentication schemes
          credentials:
            class: Database
            options: 
              table: users              # table to select accounts from
              id: user_id               # name of the user account id (pkey)
              name: user_name           # user's full name, use array if name is split between fields
              login: user_username      # login field column
              password: user_password   # password field column
              contraints:               # additional fields to match, 1 matches 1 or anything
                user_confirmed: 1
                user_visible: 1

=head1 DESCRIPTION

Dancer::Plugin::Authorize::Credentials::Database uses your Dancer::Plugin::Database 
plugin to retrieved and authenticate user account information in the database. 

=head1 METHODS

=method authorize

The authorize method (found in every authentication class) validates a user against
the defined database, tables and column using the supplied arguments and configuration file options.

=cut

sub authorize {
    
    my ($self, $options, @arguments) = @_;
    my ($login, $password) = @arguments;
    
    my $settings = $Dancer::Plugin::Authorize::settings;
    
    if ($login) {
    
    # authorize a new account using supplied credentials
        
        unless ($password) {
            $self->errors('login and password are required');
            return;
        }
    
        
    
    }
    else {
        
    # check if current user session is authorized
        
        my $user = $self->credentials;
        if (($user->{id} || $user->{login}) && !@{$user->{error}}) {
            
            return $user;
            
        }
        else {
            $self->errors('you are not authorized', 'your session may have ended');
        }
        
    }
    
}

1;