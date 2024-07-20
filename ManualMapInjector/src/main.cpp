#include <filesystem>
#include "injector.h"
#include <iostream>

#define PROCESS_NAME "hl.exe"

int main() {
	for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::current_path().append("modules"))) {
		if (entry.path().extension() == ".dll") {
			if (Inject(PROCESS_NAME, entry.path().string().c_str()))
				std::cout << "Successfully injected " << entry.path().filename().string().c_str() << '\n';
			else
				std::cout << "Failed to inject " << entry.path().filename().string().c_str() << '\n';
		}
	}

	std::cin.get();

	return 0;
}