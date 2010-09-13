# ABSTRACT: Authenticate via the Dancer configuration file!

package Dancer::Plugin::Authorize::Credentials::Config;

use strict;
use warnings;
use Dancer qw/:syntax/;

sub authorize {
    
    my ($class, $options, @arguments) = @_;
    my $settings = $class::settings;
    my ($login, $password) = @arguments;
    
    if (defined $options->{accounts}->{$login}) {
        
        if (defined $options->{accounts}->{$login}->{password}) {
            
            if ($options->{accounts}->{$login}->{password} =~ /^$password$/) {
                
                
                
            }
            
        }
        
    }
    else {
        
        return failure nedjk;
        
    }
    
}

1;