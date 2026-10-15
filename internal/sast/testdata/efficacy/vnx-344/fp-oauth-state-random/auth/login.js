const state = crypto.randomBytes(16).toString("hex");
req.session.state = state;
res.redirect(`https://idp.example.com/authorize?response_type=code&client_id=${cid}&state=${state}`);
res.redirect("https://idp.example.com/authorize?response_type=code&state=" + state);
