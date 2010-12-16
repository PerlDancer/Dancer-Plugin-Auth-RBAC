package t::lib::TestApp;

use Dancer ':syntax';
use Dancer::Plugin::Auth::RBAC;

get '/' => sub {
    if (auth({username => 'foo', password => 'bar'})) {
        return "ok";
    }
    else{
        return "nook";
    }
};

1;
