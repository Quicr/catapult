#include "catapult/trie.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unordered_set>

namespace catapult {

/**
 * @brief Pool-aware deleter implementation
 */
void TrieNodePoolDeleter::operator()(TrieNode* ptr) const {
  if (!ptr) return;
  
  auto& pool = getTrieNodePool();
  
  if (pool.is_pool_memory(ptr)) {
    // Pool allocated - destroy object first, then return memory to pool
    std::destroy_at(ptr);
    pool.deallocate_pool_memory_only(ptr);
  } else {
    // Heap allocated - use delete
    delete ptr;
  }
}

/**
 * @brief TrieNode method implementations that handle pool memory
 */
void TrieNode::setChild(char c, TrieNodePtr child) {
  // Store the TrieNodePtr directly, preserving the custom deleter
  if (child) {
    children[static_cast<unsigned char>(c)] = std::move(child);
  } else {
    children[static_cast<unsigned char>(c)] = nullptr;
  }
}

TrieNodePtr TrieNode::removeChild(char c) {
  auto child = std::move(children[static_cast<unsigned char>(c)]);
  return child;  // child is already a TrieNodePtr
}

/**
 * @brief Create a new TrieNode using pool allocation with fallback to heap
 */
TrieNodePtr createTrieNode() {
  // Try pool allocation first
  auto poolPtr = getTrieNodePool().make();
  
  if (poolPtr) {
    // Successfully allocated from pool - transfer ownership
    return TrieNodePtr(poolPtr.release(), TrieNodePoolDeleter{});
  } else {
    // Pool exhausted - fallback to heap allocation
    return TrieNodePtr(new TrieNode(), TrieNodePoolDeleter{});
  }
}

// PrefixTrie implementation - updated for optimized node structure
TrieNodePtr PrefixTrie::createNode() const {
  return createTrieNode();
}

PrefixTrie::PrefixTrie(size_t expected_size) 
  : expected_capacity_(expected_size) {
  root = createNode();
}

void PrefixTrie::insert(std::string_view pattern, std::string_view value) {
  TrieNode* current = root.get();

  for (char ch : pattern) {
    TrieNode* child = current->getChild(ch);
    if (!child) {
      current->setChild(ch, createNode());
      child = current->getChild(ch);
    }
    current = child;
  }

  if (!current->isTerminal) {
    size++;
  }

  current->isTerminal = true;
  current->value = std::string(value);
}

void PrefixTrie::insertBatch(const std::vector<std::pair<std::string_view, std::string_view>>& patterns) {
  for (const auto& [pattern, value] : patterns) {
    insert(pattern, value);
  }
}

std::vector<std::string> PrefixTrie::searchPrefix(
    std::string_view text) const {
  std::vector<std::string> matches;
  matches.reserve(expected_capacity_ > 0 ? std::min(expected_capacity_, text.size()) : 10);
  
  const TrieNode* current = root.get();

  for (size_t i = 0; i < text.length(); ++i) {
    char ch = text[i];
    const TrieNode* child = current->getChild(ch);
    if (!child) {
      break;
    }
    current = child;
    if (current->isTerminal) {
      matches.push_back(current->value);
    }
  }

  return matches;
}

std::vector<std::vector<std::string>> PrefixTrie::searchPrefixBatch(const std::vector<std::string_view>& texts) const {
  std::vector<std::vector<std::string>> results;
  results.reserve(texts.size());
  for (const auto& text : texts) {
    results.push_back(searchPrefix(text));
  }
  return results;
}

size_t PrefixTrie::getMemoryUsage() const noexcept {
  return calculateNodeMemory(root.get());
}

size_t PrefixTrie::calculateNodeMemory(const TrieNode* node) const noexcept {
  if (!node) return 0;
  
  size_t memory = sizeof(TrieNode);
  memory += node->value.capacity();
  
  // Byte children array is always allocated (full 256 bytes)
  memory += sizeof(node->children);
  
  // Recursively calculate children memory
  for (const auto& child : node->children) {
    if (child) {
      memory += calculateNodeMemory(child.get());
    }
  }
  
  return memory;
}

void PrefixTrie::clear() noexcept {
  root = createNode();
  size = 0;
}

bool PrefixTrie::containsPrefix(std::string_view text) const {
  const TrieNode* current = root.get();

  for (char ch : text) {
    const TrieNode* child = current->getChild(ch);
    if (child) {
      current = child;
      if (current->isTerminal) {
        return true;
      }
    } else {
      return false;
    }
  }

  return current->isTerminal;
}

std::vector<std::string> PrefixTrie::getAllPatterns() const {
  std::vector<std::string> patterns;
  collectPatterns(root.get(), "", patterns);
  return patterns;
}

void PrefixTrie::collectPatterns(const TrieNode* node,
                                 const std::string& prefix,
                                 std::vector<std::string>& patterns) const {
  if (node->isTerminal) {
    patterns.push_back(prefix);
  }

  auto childChars = node->getChildChars();
  for (char ch : childChars) {
    const TrieNode* child = node->getChild(ch);
    if (child) {
      collectPatterns(child, prefix + ch, patterns);
    }
  }
}

bool PrefixTrie::remove(std::string_view pattern) {
  return removeRecursive(root.get(), std::string(pattern), 0);
}

size_t PrefixTrie::removeBatch(const std::vector<std::string_view>& patterns) {
  size_t removed = 0;
  for (const auto& pattern : patterns) {
    if (remove(pattern)) {
      removed++;
    }
  }
  return removed;
}

bool PrefixTrie::removeRecursive(TrieNode* node, const std::string& pattern,
                                 size_t index) {
  if (index == pattern.length()) {
    if (node->isTerminal) {
      node->isTerminal = false;
      node->value.clear();
      size--;
      return !node->hasChildren();
    }
    return false;
  }

  char ch = pattern[index];
  TrieNode* child = node->getChild(ch);

  if (child) {
    bool shouldDeleteChild = removeRecursive(child, pattern, index + 1);

    if (shouldDeleteChild && !child->isTerminal) {
      node->removeChild(ch);
      return !node->isTerminal && !node->hasChildren();
    }
  }

  return false;
}

// SuffixTrie implementation
TrieNodePtr SuffixTrie::createNode() const {
  return createTrieNode();
}

SuffixTrie::SuffixTrie(size_t expected_size) 
  : expected_capacity_(expected_size) {
  root = createNode();
}

std::string SuffixTrie::reverse(std::string_view str) const {
  std::string reversed(str);
  std::reverse(reversed.begin(), reversed.end());
  return reversed;
}

void SuffixTrie::insert(std::string_view pattern, std::string_view value) {
  std::string reversed = reverse(pattern);
  TrieNode* current = root.get();

  for (char ch : reversed) {
    TrieNode* child = current->getChild(ch);
    if (!child) {
      current->setChild(ch, createNode());
      child = current->getChild(ch);
    }
    current = child;
  }

  if (!current->isTerminal) {
    size++;
  }

  current->isTerminal = true;
  current->value = std::string(value);
}

void SuffixTrie::insertBatch(const std::vector<std::pair<std::string_view, std::string_view>>& patterns) {
  for (const auto& [pattern, value] : patterns) {
    insert(pattern, value);
  }
}

std::vector<std::string> SuffixTrie::searchSuffix(
    std::string_view text) const {
  std::vector<std::string> matches;
  matches.reserve(expected_capacity_ > 0 ? std::min(expected_capacity_, text.size()) : 10);
  std::string reversed = reverse(text);
  const TrieNode* current = root.get();

  for (char ch : reversed) {
    const TrieNode* child = current->getChild(ch);
    if (child) {
      current = child;
      if (current->isTerminal) {
        matches.push_back(current->value);
      }
    } else {
      break;
    }
  }

  return matches;
}

std::vector<std::vector<std::string>> SuffixTrie::searchSuffixBatch(const std::vector<std::string_view>& texts) const {
  std::vector<std::vector<std::string>> results;
  results.reserve(texts.size());
  for (const auto& text : texts) {
    results.push_back(searchSuffix(text));
  }
  return results;
}

bool SuffixTrie::containsSuffix(std::string_view text) const {
  std::string reversed = reverse(text);
  const TrieNode* current = root.get();

  for (char ch : reversed) {
    const TrieNode* child = current->getChild(ch);
    if (child) {
      current = child;
      if (current->isTerminal) {
        return true;
      }
    } else {
      return false;
    }
  }

  return current->isTerminal;
}

std::vector<std::string> SuffixTrie::getAllPatterns() const {
  std::vector<std::string> patterns;
  collectPatterns(root.get(), "", patterns);
  // Reverse all collected patterns
  for (auto& pattern : patterns) {
    pattern = reverse(pattern);
  }
  return patterns;
}

void SuffixTrie::collectPatterns(const TrieNode* node,
                                 const std::string& prefix,
                                 std::vector<std::string>& patterns) const {
  if (node->isTerminal) {
    patterns.push_back(prefix);
  }

  auto childChars = node->getChildChars();
  for (char ch : childChars) {
    const TrieNode* child = node->getChild(ch);
    if (child) {
      collectPatterns(child, prefix + ch, patterns);
    }
  }
}

bool SuffixTrie::remove(std::string_view pattern) {
  std::string reversed = reverse(pattern);
  return removeRecursive(root.get(), reversed, 0);
}

bool SuffixTrie::removeRecursive(TrieNode* node, const std::string& pattern,
                                 size_t index) {
  if (index == pattern.length()) {
    if (node->isTerminal) {
      node->isTerminal = false;
      node->value.clear();
      size--;
      return !node->hasChildren();
    }
    return false;
  }

  char ch = pattern[index];
  TrieNode* child = node->getChild(ch);

  if (child) {
    bool shouldDeleteChild = removeRecursive(child, pattern, index + 1);

    if (shouldDeleteChild && !child->isTerminal) {
      node->removeChild(ch);
      return !node->isTerminal && !node->hasChildren();
    }
  }

  return false;
}

}  // namespace catapult