# ABSTRACT: Dancer::Plugin::Authorize authentication via the Dancer configuration file!

package Dancer::Plugin::Authorize::Credentials::Config;

use strict;
use warnings;
use base qw/Dancer::Plugin::Authorize::Credentials/;

=head1 SYNOPSIS

    plugins:
      Authorize:
        mykeyword: 
          credentials:
            class: Config
            options: 
              accounts:
                user01:
                  name: Joe Schmoe
                  password: foobar
                  roles:
                    - guest
                    - user
                user02:
                  name: Jacque Fock
                  password: barbaz
                  roles:
                    - admin
                    
    # in Dancer application
    
    if (mykeyword()) {
        # authenticated
        return 1;
    }

=head1 DESCRIPTION

Dancer::Plugin::Authorize::Credentials::Config uses your Dancer application
configuration file as the application's user management system.

** Note! This authentication class sets the user's roles automatically. **

=head1 METHODS

=method authorize

The authorize method (found in every authentication class) validates a user against
the defined datastore using the supplied arguments and configuration file options.

=cut

sub authorize {
    
    my ($self, $options, @arguments) = @_;
    my ($login, $password) = @arguments;
    
    my $settings = $Dancer::Plugin::Authorize::settings;
    
    if ($login) {
    
    # authorize a new account using supplied credentials
        
        my $accounts = $options->{accounts};
        
        unless ($password) {
            $self->errors('login and password are required');
            return;
        }
    
        if (defined $accounts->{$login}) {
            
            if (defined $accounts->{$login}->{password}) {
                
                if ($accounts->{$login}->{password} =~ /^$password$/) {
                    
                    my $session_data = {
                        id    => $login,
                        name  => $accounts->{$login}->{name} || ucfirst($login),
                        login => $login,
                        roles => [@{$accounts->{$login}->{roles}}],
                        error => []
                    };
                    return $self->credentials($session_data);
                    
                }
                else {
                    $self->errors('login and/or password is invalid');
                }
                
            }
            else {
                $self->errors('attempting to access as inaccessible account');
            }
            
        }
        else {
            $self->errors('login and/or password is invalid');
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