class Loops {
    void a(int n) {
        int i = 0;
        while (i < n) {
            work(i);
            i++;
        }
    }

    void b(int lo, int hi) {
        while (lo < hi) {
            swap(lo, hi);
            hi--;
        }
    }

    void c(int i, int n) {
        while (i < n) {
            ++i;
        }
    }

    Node d(Node node, Node stop) {
        while (node != stop) {
            node = node.next;
        }
        return node;
    }
}
