# ABSTRACT: Dancer::Plugin::Authorize authentication via the Dancer::Plugin::Database!

package Dancer::Plugin::Authorize::Credentials::Database;

use strict;
use warnings;
use base qw/Dancer::Plugin::Authorize::Credentials/;
use Dancer::Plugin::Database;

=head1 SYNOPSIS

    plugins:
      Authorize:
        auth: # keyword allows one to setup multiple authentication schemes
          credentials:
            class: Database
            options:
              user:
                query: select * from users where user_username = ? and user_password = PASSWORD(?)
                id: user_id               # user account identifier (usually the pkey)
                name: user_name           # user's full name, use array if name is split between fields
                login: user_username      # login database field
              roles:
                query: select * from user_roles where user_id = ?
                role: role_name           # role name database field

=head1 DESCRIPTION

Dancer::Plugin::Authorize::Credentials::Database uses your Dancer::Plugin::Database 
plugin to retrieved and authenticate user account information in the database.

** Note! This authentication class sets the user's roles automatically, if defined. **

If you intend to establish a role-based system within your database and would like
to provide a fine level of ganularity, please consider the following:

    # database RBAC (role-based access control) schema
    
    users
        user_id, user_name, user_login, user_password, ...
        
    roles
        role_id, role_name, ...
        
    user_roles
        user_role_id, user_id, role_id, ...
        
    role_operations
        role_operation_id, role_id, operation_name, ...
        
    role_operation_actions
        role_action_id, role_id, role_operation_id, action_name, ...

=head1 METHODS

=method authorize

The authorize method (found in every authentication class) validates a user against
the defined database, tables and column using the supplied arguments and configuration
file options.

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
    
        my $sth  =
            database->prepare($options->{user}->{query});
            $sth->execute($login, $password);
            
        my $user = $sth->fetchrow_hashref;
        
        if ($user) {
            my $name  = undef;
            my @roles = ();
            my $id    = $user->{$options->{user}->{login}};
            my $login = $user->{$options->{user}->{id}};
            if (ref($user->{$options->{user}->{name}}) eq "ARRAY") {
                my @names = @{ $user->{$options->{user}->{name}} };
                @names = map { $user->{$_} } @names;
                $name = join ' ', @names;
            }
            else {
                $name = $user->{$options->{user}->{name}};
            }
            
            if ($id && $options->{roles}) {
                # get roles if specified
                my $sth  =
                database->prepare($options->{roles}->{query});
                $sth->execute($id);
                
                my $roles = $sth->fetchrow_hashref;
                
                while (my $role = $sth->fetchrow_hashref) {
                    push @roles, $role->{$options->{roles}->{role}};
                }
            }
            
            # set authentication
            my $session_data = {
                id    => $id,
                name  => $name || ucfirst($login),
                login => $login,
                roles => [@roles],
                error => []
            };
            return $self->credentials($session_data);
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