#include <iostream>
#include <chrono>  // 包含用于时间测量的库

using namespace std;
using namespace std::chrono;

int main() {
    // 获取当前时间，作为开始时间
    auto start = high_resolution_clock::now();

    // 你要计时的操作：这里是简单的等待1秒
    this_thread::sleep_for(seconds(1));

    // 获取结束时间
    auto end = high_resolution_clock::now();

    // 计算时间差（单位：毫秒）
    auto duration = duration_cast<milliseconds>(end - start);

    // 输出结果
    cout << "操作耗时: " << duration.count() << " 毫秒" << endl;

    return 0;
}
