<?php

namespace ChastePhp\LaravelJwt;

use ChastePhp\LaravelExtras\Auth\JwtGuard;
use ChastePhp\LaravelJwt\Console\KeyGenerateCommand;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class JwtServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        Auth::extend('jwt', function ($app, $name, array $config) {

            $guard = new JwtGuard(Auth::createUserProvider($config['provider']), $app['request']);

            $this->app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

        if ($this->app->runningInConsole()) {
            $this->commands([
                KeyGenerateCommand::class,
            ]);
        }
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        //
        $source = realpath(__DIR__.'/config/jwt.php');

        $this->publishes([$source => config_path('jwt.php')], 'jwt');

        $this->mergeConfigFrom($source, 'jwt');
    }
}
