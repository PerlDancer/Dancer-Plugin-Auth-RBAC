package t::lib::TestApp;

use Dancer ':syntax';
use Dancer::Plugin::Auth::RBAC;

get '/' => sub {

    my $username = params->{username};
    my $password = params->{password};

    if (auth({username => $username, password => $password})) {
        return "ok";
    }
    else{
        return "nook";
    }
};

1;
