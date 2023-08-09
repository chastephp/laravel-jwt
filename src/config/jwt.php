<?php


return [

    'secret' => env('JWT_SECRET'),

    /**
     * seconds
     */
    'ttl' => env('JWT_TTL', 86400 * 30),


    'algo' => env('JWT_ALGO', 'HS256'),

];
