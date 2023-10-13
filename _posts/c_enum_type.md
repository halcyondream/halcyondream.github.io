```c++
#include <iostream>

enum class T {A=1, B=1};

template <typename E>
decltype(auto) tToInt(E const value) {
    return static_cast<typename std::underlying_type<E>::type>(value);
}

template <typename E>
decltype(auto) operator&(E const x, E const y) {
    return tToInt(x) & tToInt(y);
}

int main() {
    std::cout << (T::A & T::B) << std::endl;
}

```

