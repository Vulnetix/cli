struct Holder { Entry *entry_; void reset(); };
void Holder::reset()
{
    delete entry_;
    log_reset();
~>    delete entry_;
}
