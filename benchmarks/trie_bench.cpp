#include <benchmark/benchmark.h>
#include "catapult/trie.hpp"
#include <vector>
#include <string>
#include <random>

using namespace catapult;

// Benchmark-specific PrefixTrie for scalability tests
using BenchmarkPrefixTrie = PrefixTrie;

// Test data generators
std::vector<std::string> generateRandomStrings(size_t count, size_t minLength, size_t maxLength) {
    std::vector<std::string> strings;
    strings.reserve(count);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> lengthDist(minLength, maxLength);
    std::uniform_int_distribution<int> charDist('a', 'z');
    
    for (size_t i = 0; i < count; ++i) {
        size_t length = lengthDist(gen);
        std::string str;
        str.reserve(length);
        
        for (size_t j = 0; j < length; ++j) {
            str += static_cast<char>(charDist(gen));
        }
        strings.push_back(str);
    }
    
    return strings;
}

std::vector<std::string> generatePrefixPatterns() {
    return {
        "http://", "https://", "ftp://", "file://",
        "api/v1/", "api/v2/", "api/", 
        "user/", "admin/", "guest/",
        "en", "fr", "de", "es", "it"
    };
}

std::vector<std::string> generateSuffixPatterns() {
    return {
        ".com", ".org", ".net", ".edu", ".gov",
        ".html", ".css", ".js", ".png", ".jpg",
        "/index", "/home", "/about", "/contact",
        "admin", "user", "guest"
    };
}

std::vector<std::string> generateTestTexts() {
    return {
        "https://example.com/api/v1/users/admin",
        "http://test.org/index.html",
        "ftp://files.net/documents/report.pdf",
        "api/v2/admin/settings",
        "user/profile/edit.php",
        "https://secure.edu/login/guest",
        "file://localhost/home/user/test.js"
    };
}

// PrefixTrie Benchmarks

static void BM_PrefixTrie_Insert_Small(benchmark::State& state) {
    auto patterns = generatePrefixPatterns();
    
    for (auto _ : state) {
        PrefixTrie trie;
        state.PauseTiming();
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_PrefixTrie_Insert_Small);

static void BM_PrefixTrie_Insert_Medium(benchmark::State& state) {
    auto patterns = generateRandomStrings(100, 3, 15);
    
    for (auto _ : state) {
        PrefixTrie trie;
        state.PauseTiming();
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_PrefixTrie_Insert_Medium);

static void BM_PrefixTrie_Insert_Large(benchmark::State& state) {
    auto patterns = generateRandomStrings(1000, 5, 25);
    
    for (auto _ : state) {
        PrefixTrie trie;
        state.PauseTiming();
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_PrefixTrie_Insert_Large);

static void BM_PrefixTrie_SearchPrefix_Hit(benchmark::State& state) {
    PrefixTrie trie;
    auto patterns = generatePrefixPatterns();
    auto texts = generateTestTexts();
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : texts) {
            auto result = trie.searchPrefix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_PrefixTrie_SearchPrefix_Hit);

static void BM_PrefixTrie_SearchPrefix_Miss(benchmark::State& state) {
    PrefixTrie trie;
    auto patterns = generatePrefixPatterns();
    std::vector<std::string> missTexts = {"xyz://invalid", "unknown/path", "random.text"};
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : missTexts) {
            auto result = trie.searchPrefix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_PrefixTrie_SearchPrefix_Miss);

static void BM_PrefixTrie_ContainsPrefix_Hit(benchmark::State& state) {
    PrefixTrie trie;
    auto patterns = generatePrefixPatterns();
    auto texts = generateTestTexts();
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : texts) {
            bool result = trie.containsPrefix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_PrefixTrie_ContainsPrefix_Hit);

static void BM_PrefixTrie_ContainsPrefix_Miss(benchmark::State& state) {
    PrefixTrie trie;
    auto patterns = generatePrefixPatterns();
    std::vector<std::string> missTexts = {"xyz://invalid", "unknown/path", "random.text"};
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : missTexts) {
            bool result = trie.containsPrefix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_PrefixTrie_ContainsPrefix_Miss);

static void BM_PrefixTrie_GetAllPatterns(benchmark::State& state) {
    PrefixTrie trie;
    auto patterns = generateRandomStrings(state.range(0), 3, 10);
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        auto result = trie.getAllPatterns();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_PrefixTrie_GetAllPatterns)->Range(10, 1000);

static void BM_PrefixTrie_Remove(benchmark::State& state) {
    auto patterns = generateRandomStrings(100, 3, 10);
    
    for (auto _ : state) {
        state.PauseTiming();
        PrefixTrie trie;
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            bool result = trie.remove(pattern);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_PrefixTrie_Remove);

// SuffixTrie Benchmarks

static void BM_SuffixTrie_Insert_Small(benchmark::State& state) {
    auto patterns = generateSuffixPatterns();
    
    for (auto _ : state) {
        SuffixTrie trie;
        state.PauseTiming();
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_SuffixTrie_Insert_Small);

static void BM_SuffixTrie_Insert_Medium(benchmark::State& state) {
    auto patterns = generateRandomStrings(100, 3, 15);
    
    for (auto _ : state) {
        SuffixTrie trie;
        state.PauseTiming();
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_SuffixTrie_Insert_Medium);

static void BM_SuffixTrie_Insert_Large(benchmark::State& state) {
    auto patterns = generateRandomStrings(1000, 5, 25);
    
    for (auto _ : state) {
        SuffixTrie trie;
        state.PauseTiming();
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_SuffixTrie_Insert_Large);

static void BM_SuffixTrie_SearchSuffix_Hit(benchmark::State& state) {
    SuffixTrie trie;
    auto patterns = generateSuffixPatterns();
    auto texts = generateTestTexts();
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : texts) {
            auto result = trie.searchSuffix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_SuffixTrie_SearchSuffix_Hit);

static void BM_SuffixTrie_SearchSuffix_Miss(benchmark::State& state) {
    SuffixTrie trie;
    auto patterns = generateSuffixPatterns();
    std::vector<std::string> missTexts = {"invalidxyz", "pathunknown", "textrandom"};
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : missTexts) {
            auto result = trie.searchSuffix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_SuffixTrie_SearchSuffix_Miss);

static void BM_SuffixTrie_ContainsSuffix_Hit(benchmark::State& state) {
    SuffixTrie trie;
    auto patterns = generateSuffixPatterns();
    auto texts = generateTestTexts();
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : texts) {
            bool result = trie.containsSuffix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_SuffixTrie_ContainsSuffix_Hit);

static void BM_SuffixTrie_ContainsSuffix_Miss(benchmark::State& state) {
    SuffixTrie trie;
    auto patterns = generateSuffixPatterns();
    std::vector<std::string> missTexts = {"invalidxyz", "pathunknown", "textrandom"};
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : missTexts) {
            bool result = trie.containsSuffix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_SuffixTrie_ContainsSuffix_Miss);

static void BM_SuffixTrie_GetAllPatterns(benchmark::State& state) {
    SuffixTrie trie;
    auto patterns = generateRandomStrings(state.range(0), 3, 10);
    
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        auto result = trie.getAllPatterns();
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_SuffixTrie_GetAllPatterns)->Range(10, 1000);

static void BM_SuffixTrie_Remove(benchmark::State& state) {
    auto patterns = generateRandomStrings(100, 3, 10);
    
    for (auto _ : state) {
        state.PauseTiming();
        SuffixTrie trie;
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        state.ResumeTiming();
        
        for (const auto& pattern : patterns) {
            bool result = trie.remove(pattern);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_SuffixTrie_Remove);

// Comparison Benchmarks

static void BM_Trie_Insert_Comparison(benchmark::State& state) {
    const int trieType = state.range(0); // 0=Prefix, 1=Suffix
    auto patterns = generateRandomStrings(100, 5, 15);
    
    for (auto _ : state) {
        if (trieType == 0) {
            PrefixTrie trie;
            for (const auto& pattern : patterns) {
                trie.insert(pattern, pattern);
            }
            benchmark::DoNotOptimize(trie);
        } else {
            SuffixTrie trie;
            for (const auto& pattern : patterns) {
                trie.insert(pattern, pattern);
            }
            benchmark::DoNotOptimize(trie);
        }
    }
}
BENCHMARK(BM_Trie_Insert_Comparison)->DenseRange(0, 1);

static void BM_Trie_Search_Comparison(benchmark::State& state) {
    const int trieType = state.range(0); // 0=Prefix, 1=Suffix
    auto patterns = generateRandomStrings(100, 3, 10);
    auto texts = generateTestTexts();
    
    if (trieType == 0) {
        PrefixTrie trie;
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        
        for (auto _ : state) {
            for (const auto& text : texts) {
                auto result = trie.searchPrefix(text);
                benchmark::DoNotOptimize(result);
            }
        }
    } else {
        SuffixTrie trie;
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        
        for (auto _ : state) {
            for (const auto& text : texts) {
                auto result = trie.searchSuffix(text);
                benchmark::DoNotOptimize(result);
            }
        }
    }
}
BENCHMARK(BM_Trie_Search_Comparison)->DenseRange(0, 1);

// Scalability Benchmarks

static void BM_PrefixTrie_Insert_Scalability(benchmark::State& state) {
    auto patterns = generateRandomStrings(state.range(0), 5, 15);
    
    for (auto _ : state) {
        BenchmarkPrefixTrie trie;
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_PrefixTrie_Insert_Scalability)->Range(10, 10000);

static void BM_PrefixTrie_Search_Scalability(benchmark::State& state) {
    const size_t numPatterns = state.range(0);
    auto patterns = generateRandomStrings(numPatterns, 5, 15);
    auto texts = generateRandomStrings(100, 10, 20);
    
    BenchmarkPrefixTrie trie;
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : texts) {
            auto result = trie.searchPrefix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_PrefixTrie_Search_Scalability)->Range(10, 10000);

static void BM_SuffixTrie_Insert_Scalability(benchmark::State& state) {
    auto patterns = generateRandomStrings(state.range(0), 5, 15);
    
    for (auto _ : state) {
        SuffixTrie trie;
        for (const auto& pattern : patterns) {
            trie.insert(pattern, pattern);
        }
        benchmark::DoNotOptimize(trie);
    }
}
BENCHMARK(BM_SuffixTrie_Insert_Scalability)->Range(10, 10000);

static void BM_SuffixTrie_Search_Scalability(benchmark::State& state) {
    const size_t numPatterns = state.range(0);
    auto patterns = generateRandomStrings(numPatterns, 5, 15);
    auto texts = generateRandomStrings(100, 10, 20);
    
    SuffixTrie trie;
    for (const auto& pattern : patterns) {
        trie.insert(pattern, pattern);
    }
    
    for (auto _ : state) {
        for (const auto& text : texts) {
            auto result = trie.searchSuffix(text);
            benchmark::DoNotOptimize(result);
        }
    }
}
BENCHMARK(BM_SuffixTrie_Search_Scalability)->Range(10, 10000);