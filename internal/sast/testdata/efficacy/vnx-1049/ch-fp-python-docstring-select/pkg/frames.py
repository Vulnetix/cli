def merge_frames(frames, how="inner"):
    """
    Select which frames to join and how. Each pair is passed to join in
    order: join the first two, join the result with the third, then join
    (optionally) any remaining frames, and join the tail last.
    """
    out = frames[0]
    for f in frames[1:]:
        out = out.join(f, how=how)
    return out
