﻿using System;
using System.Runtime.CompilerServices;
using System.Web;

namespace Owin.Security.Keycloak.Caching
{
    public abstract class Cache
    {
        protected readonly TimeSpan DefaultCacheLife = new TimeSpan(0, 30, 0); // 30 Minutes

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected System.Web.Caching.Cache GetCache()
        {
            return HttpRuntime.Cache;
        }
    }
}