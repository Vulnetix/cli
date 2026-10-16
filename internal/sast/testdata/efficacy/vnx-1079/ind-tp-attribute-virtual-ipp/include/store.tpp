template <class T>
~>class Store {
public:
    [[nodiscard]] virtual T get(int i) const;
    ~Store() { release(); }
private:
    void release();
    T *data_ = nullptr;
};
