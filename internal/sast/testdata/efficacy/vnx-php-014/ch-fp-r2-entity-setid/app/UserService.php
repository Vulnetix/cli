<?php
class UserService
{
    public function update(Request $request)
    {
        $user = new User();
        $user->setId($request->input('id'));
        $this->session->setId(bin2hex(random_bytes(16)));
        Session::setId(Str::random(40));
    }
}

class StartSessionMiddleware
{
    public function getSession(Request $request)
    {
        return tap($this->manager->driver(), function ($session) use ($request) {
            $session->setId($request->cookies->get($session->getName()));
        });
    }
}
