#include <boost/stacktrace/stacktrace.hpp>
#include <iostream>

int main()
{
  boost::stacktrace::stacktrace st;
  std::cout << st << std::flush;
}
