package t::lib::TestApp::Schema::Role;

use strict;
use warnings;
use base 'DBIx::Class';

__PACKAGE__->load_components(qw/ Core /);

__PACKAGE__->table('role');
__PACKAGE__->add_columns(qw/id role/);
__PACKAGE__->set_primary_key('id');

1;
