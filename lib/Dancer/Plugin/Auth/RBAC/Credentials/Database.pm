# ABSTRACT: Dancer::Plugin::Auth::RBAC authentication via Database!

package Dancer::Plugin::Auth::RBAC::Credentials::Database;

use strict;
use warnings;
use base qw/Dancer::Plugin::Auth::RBAC::Credentials/;
use Dancer::Plugin::Database;
use Dancer::Logger;

=head1 SYNOPSIS

    # in your app code
    my $auth = auth($login, $password);
    if ($auth) {
        # login successful
    }
    
    # use your own encryption (if the user account password is encrypted)
    my $auth = auth($login, encrypt($password));
    if ($auth) {
        # login successful
    }

=head1 DESCRIPTION

Dancer::Plugin::Auth::RBAC::Credentials::Database uses your Database database
connection as the application's user management system.

=head1 CONFIGURATION

    plugins:
      Database:
        driver: 'Pg'
        database: 'test'
        username: 'root'
        password: '****'
      Auth::RBAC:
        credentials:
          class: Database
          
Sometime you might define multiple connections for the Database plugin, make
sure you tell the Auth::RBAC plugin about it... e.g.

    plugins:
      Database:
        foo:
          driver: 'sqlite'
          database: 'example1.db'
        bar:
          driver: 'Pg'
          database: 'test'
          username: 'root'
          password: '****'
      Auth::RBAC:
        credentials:
          class: Database
          options:
            handle: bar


Please see L<Dancer::Plugin::Database> for a list of all available connection
options and arguments.

=head1 DATABASE SETUP
    
    # You'll need to create three tables to store user details, as follows.
    # Feel free to include other fields in the users table.
    
    CREATE TABLE "users" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "name" TEXT,
    "login" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "roles" TEXT
    );

    CREATE TABLE "roles" (
    "id" SERIAL NOT NULL PRIMARY KEY,
    "role" TEXT NOT NULL
    );

    CREATE TABLE "user_roles" (
    "user_id" NOT NULL,
    "role_id" NOT NULL
    );

    # Create some roles:
    INSERT INTO roles (id, role) VALUES ('1', 'users');
    INSERT INTO roles (id, role) VALUES ('2', 'admin');
   
    # Create an initial admin user, and assign roles to them
    INSERT INTO users (id, name, login, password, roles)
        VALUES (1. 'Administrator', 'admin', '*****');
    INSERT INTO user_roles (user_id, role_id) VALUES (1,1);
    INSERT INTO user_roles (user_id, role_id) VALUES (1,2);


=method authorize

The authorize method (found in every authentication class) validates a user against
the defined datastore using the supplied arguments and configuration file options.

=cut

sub authorize {
    
    my ($self, $options, @arguments) = @_;
    my ($login, $password) = @arguments;

    # Firstly, if we're not given a username, check the session for credentials,
    # to see if we're already authed:
    if (!$login) {
        my $user = $self->credentials;
        if ($user->{id} || $user->{login} && !@{$user->{error}}) {
            return $user;
        } else {
            $self->errors("Session ended?");
            return 0;
        }
    }

    # Right, we need to process a login.
    if (!$login || !$password) {
        $self->errors('login and password are required');
        return 0;
    }
    
    my $settings = $Dancer::Plugin::Auth::RBAC::settings;
    
    # Work out our field names, either using the defaults, or ones supplied in
    # our config
    my $field_map = _field_mappings($settings);
    my $tables = $field_map->{tables};
    my $fields = $field_map->{fields};

    # First, find the user record
    my $user = database->quick_select($tables->{user}
        { $fields->{user}{login} => $login }
    );

    # If we found no record, they don't exist
    if (!$user) {
        $self->errors('No such user');
        return 0;
    }


    # Next, check their password.  If we're using crypted passwords, use
    # Crypt::SaltedHash to compare it, if not, it's a straight string comparison
    my $db_password = $user->{ $fields->{user}{password} };
    if ($settings->{crypted_passwords}) {
        if (!Dancer::ModuleLoader->load('Crypt::SaltedHash')) {
            $self->errors(
                "Need Crypt::SaltedHash to verify crypted passwords!"
            );
            return;
        }
        if (!Crypt::SaltedHash->validate($db_password, $password)) {
            $self->errors("Invalid password");
            return 0;
        }
    } else {
        if ($db_password ne $password) {
            $self->errors("Invalid password");
            return 0;
        }
    }

    # OK, we found a matching user record, and their password was OK.

    # If the user doesn't want roles support, don't go looking for roles, just
    # give them a sane default of 'user' and return the record
    if ($settings->{disable_roles}) {
        $user->{roles} = ['user'];
        return $user;
    }

    # Right, assemble the query we need to work out what roles this user has:
    my $sth = database($options->{handle})->prepare(<<QUERY);
SELECT * FROM $tables->{user_role}
LEFT JOIN $tables->{role} 
ON $tables->{user_roles}.$fields->{user_role}{role_id} 
    = $tables->{role}.$fields->{role}{id}
WHERE $tables->{user_role}.$fields->{user_roles_user_id} = ?
QUERY

    my @roles;
    if ($sth->execute($user->{ $fields->{user}{id} })) {
        while (my $role = $sth->fetchrow_hashref) {
            push @roles, $role->{ $fields->{role}{role} };
        }
    } else {
        Dancer::Logger::error "Failed to fetch roles: " . database->errstr;
        $self->errors("Failed to fetch roles");
        return 0;
    }

    # Right, done
    $user->{roles} = \@roles;
    return $self->credentials($user);
    
}



=head1 Custom table / field names

By default, you must have tables named C<users>, C<roles> and C<user_roles> with
appropriate field names.  This may not be ideal, though, so you can if required
provide configuration to override them.

The configuration example below shows the default table and field names; it
should be clear how to modify to suit your requirements, should you need to do
so.

(If you are starting a new application from scratch, it's recommended you just
use the defaults and set up your table schema as per the example SQL provided.)

    plugins:
        Auth::RBAC:
            user_table: 'user'
            role_table: 'role'
            user_role_table': 'user_role'
            user_id_field: 'id'
            user_login_field: 'login'
            user_password_field: 'password'
            role_id_field: 'id'
            role_name_field: 'role'
            user_role_user_id_field: 'user_id'
            user_role_role_id_field: 'role_id'

=cut

# Given our settings from the config, return a hashref mapping table and
# key names, or our default names.
sub _field_map {
    my $settings = shift;
    my %tables;
    $tables{$_} = database->quote_identifer(
        $settings->{$_ . '_table'} || $_
    ) for qw(user role user_role);

    my %fields;
    $fields{user}{$_} = database->quote_identifier(
        $settings->{ "user_" . $_ . "_field" } || $_
    ) for qw(id login password);


    $fields{user_role}{$_} = database->quote_identifer(
        $settings->{'user_role_' . $_ . '_field'} || $_
    ) for qw(user_id role_id);
    $fields{role}{$_} = database->quote_identifier(
        $settings->{'role_' . $_ . '_field'} || $_
    ) for qw(id role);

    # Right, return that:
    return {
        tables => \%tables,
        fields => \%fields,
    };
}


1;
