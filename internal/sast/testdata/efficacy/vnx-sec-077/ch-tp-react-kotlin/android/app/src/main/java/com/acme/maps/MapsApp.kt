package com.acme.maps

import com.mapbox.common.MapboxOptions

class MapsApp : android.app.Application() {
    override fun onCreate() {
        super.onCreate()
~>        MapboxOptions.accessToken = "@@sample:pk\.eyJ1Ijoi[A-Za-z0-9]{12}IiwiYSI6I[A-Za-z0-9_-]{30}In0\.[A-Za-z0-9_-]{22}@@"
    }
}
