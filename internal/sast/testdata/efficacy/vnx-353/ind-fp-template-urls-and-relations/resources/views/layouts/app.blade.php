<!DOCTYPE html>
<html lang="{{ app()->getLocale() }}">
<head>
    <link rel="canonical" href="https://shop.example.com/{{ request()->path() }}">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="icon" href="https://static.example.com/favicon.png">
    <link rel="alternate" type="application/rss+xml" href="https://shop.example.com/feed.xml">
    <link rel="stylesheet" href="{{ asset('css/app.css') }}">
    <script src="{{ mix('js/app.js') }}" defer></script>
    <script src="{{ config('app.cdn_url') }}/js/widget.js"></script>
</head>
<body>
    <a href="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js">Download jQuery</a>
    @yield('content')
</body>
</html>
