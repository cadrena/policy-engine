package memory

import (
	"cmp"
	"time"

	"github.com/conductera/dsl"
	policyengine "github.com/conductera/policy-engine"
	"github.com/conductera/policy-engine/store"
)

// revisionNode is an immutable AVL index ordered by stable pagination key.
type revisionKey struct {
	publishedAt time.Time
	id          string
}

type revisionNode struct {
	left, right *revisionNode
	height      int
	key         revisionKey
	record      store.RevisionRecord
}

func revisionHeight(node *revisionNode) int {
	if node == nil {
		return 0
	}
	return node.height
}

func compareRevisionKey(left, right revisionKey) int {
	if left.publishedAt.Before(right.publishedAt) {
		return -1
	}
	if left.publishedAt.After(right.publishedAt) {
		return 1
	}
	return cmp.Compare(left.id, right.id)
}

func revisionKeyFor(record store.RevisionRecord) revisionKey {
	metadata := record.Metadata()
	return revisionKey{publishedAt: metadata.PublishedAt(), id: metadata.ID()}
}

func newRevisionNode(key revisionKey, record store.RevisionRecord, left, right *revisionNode) *revisionNode {
	return &revisionNode{
		key: key, record: record, left: left, right: right,
		height: 1 + max(revisionHeight(left), revisionHeight(right)),
	}
}

func revisionBalance(node *revisionNode) int {
	return revisionHeight(node.left) - revisionHeight(node.right)
}

func revisionRotateRight(node *revisionNode) *revisionNode {
	pivot := node.left
	return newRevisionNode(
		pivot.key,
		pivot.record,
		pivot.left,
		newRevisionNode(node.key, node.record, pivot.right, node.right),
	)
}

func revisionRotateLeft(node *revisionNode) *revisionNode {
	pivot := node.right
	return newRevisionNode(
		pivot.key,
		pivot.record,
		newRevisionNode(node.key, node.record, node.left, pivot.left),
		pivot.right,
	)
}

func revisionRebalance(node *revisionNode) *revisionNode {
	if revisionBalance(node) > 1 {
		if revisionBalance(node.left) < 0 {
			node = newRevisionNode(node.key, node.record, revisionRotateLeft(node.left), node.right)
		}
		return revisionRotateRight(node)
	}
	if revisionBalance(node) < -1 {
		if revisionBalance(node.right) > 0 {
			node = newRevisionNode(node.key, node.record, node.left, revisionRotateRight(node.right))
		}
		return revisionRotateLeft(node)
	}
	return node
}

func revisionSet(node *revisionNode, record store.RevisionRecord) *revisionNode {
	key := revisionKeyFor(record)
	if node == nil {
		return newRevisionNode(key, record, nil, nil)
	}
	switch order := compareRevisionKey(key, node.key); {
	case order < 0:
		return revisionRebalance(newRevisionNode(node.key, node.record, revisionSet(node.left, record), node.right))
	case order > 0:
		return revisionRebalance(newRevisionNode(node.key, node.record, node.left, revisionSet(node.right, record)))
	default:
		return newRevisionNode(key, record, node.left, node.right)
	}
}

// revisionPage visits at most limit records after the continuation key and one
// additional candidate to determine whether another page exists. visited is an
// internal deterministic work counter used by structure tests.
func revisionPage(
	root *revisionNode,
	after revisionKey,
	hasAfter bool,
	limit int,
	visit func(store.RevisionRecord) bool,
) (visited int, more bool) {
	emitted := 0
	var walk func(*revisionNode) bool
	walk = func(node *revisionNode) bool {
		if node == nil {
			return true
		}
		visited++
		if hasAfter && compareRevisionKey(node.key, after) <= 0 {
			return walk(node.right)
		}
		if !walk(node.left) {
			return false
		}
		if emitted == limit {
			more = true
			return false
		}
		emitted++
		if !visit(node.record) {
			return false
		}
		return walk(node.right)
	}
	walk(root)
	return visited, more
}

// dataVersion is an immutable structurally-shared namespace view. A snapshot
// pins this pointer in O(1); commits replace only search paths touched by the
// bounded mutation.
type dataVersion struct {
	generation uint64
	tuples     *tupleNode
	attributes *attributeEntityNode
}

type tupleNode struct {
	left, right *tupleNode
	height      int
	key         dsl.Tuple
	value       policyengine.RelationshipTuple
}

func tupleHeight(node *tupleNode) int {
	if node == nil {
		return 0
	}
	return node.height
}

func newTupleNode(key dsl.Tuple, value policyengine.RelationshipTuple, left, right *tupleNode) *tupleNode {
	return &tupleNode{key: key, value: value, left: left, right: right, height: 1 + max(tupleHeight(left), tupleHeight(right))}
}

func compareEntity(left, right dsl.EntityRef) int {
	if order := cmp.Compare(left.Type, right.Type); order != 0 {
		return order
	}
	return cmp.Compare(left.ID, right.ID)
}

func compareSubject(left, right dsl.SubjectRef) int {
	if order := cmp.Compare(left.Type, right.Type); order != 0 {
		return order
	}
	if order := cmp.Compare(left.ID, right.ID); order != 0 {
		return order
	}
	return cmp.Compare(left.Relation, right.Relation)
}

func compareTuple(left, right dsl.Tuple) int {
	if order := compareEntity(left.Resource, right.Resource); order != 0 {
		return order
	}
	if order := cmp.Compare(left.Relation, right.Relation); order != 0 {
		return order
	}
	return compareSubject(left.Subject, right.Subject)
}

func compareTupleBucket(tuple dsl.Tuple, resource dsl.EntityRef, relation string) int {
	if order := compareEntity(tuple.Resource, resource); order != 0 {
		return order
	}
	return cmp.Compare(tuple.Relation, relation)
}

func tupleBalance(node *tupleNode) int { return tupleHeight(node.left) - tupleHeight(node.right) }

func tupleRotateRight(node *tupleNode) *tupleNode {
	pivot := node.left
	newRight := newTupleNode(node.key, node.value, pivot.right, node.right)
	return newTupleNode(pivot.key, pivot.value, pivot.left, newRight)
}

func tupleRotateLeft(node *tupleNode) *tupleNode {
	pivot := node.right
	newLeft := newTupleNode(node.key, node.value, node.left, pivot.left)
	return newTupleNode(pivot.key, pivot.value, newLeft, pivot.right)
}

func tupleRebalance(node *tupleNode) *tupleNode {
	balance := tupleBalance(node)
	if balance > 1 {
		if tupleBalance(node.left) < 0 {
			left := tupleRotateLeft(node.left)
			node = newTupleNode(node.key, node.value, left, node.right)
		}
		return tupleRotateRight(node)
	}
	if balance < -1 {
		if tupleBalance(node.right) > 0 {
			right := tupleRotateRight(node.right)
			node = newTupleNode(node.key, node.value, node.left, right)
		}
		return tupleRotateLeft(node)
	}
	return node
}

func tupleSet(node *tupleNode, key dsl.Tuple, value policyengine.RelationshipTuple) *tupleNode {
	if node == nil {
		return newTupleNode(key, value, nil, nil)
	}
	switch order := compareTuple(key, node.key); {
	case order < 0:
		return tupleRebalance(newTupleNode(node.key, node.value, tupleSet(node.left, key, value), node.right))
	case order > 0:
		return tupleRebalance(newTupleNode(node.key, node.value, node.left, tupleSet(node.right, key, value)))
	default:
		return newTupleNode(key, value, node.left, node.right)
	}
}

func tupleMin(node *tupleNode) *tupleNode {
	for node.left != nil {
		node = node.left
	}
	return node
}

func tupleDelete(node *tupleNode, key dsl.Tuple) *tupleNode {
	if node == nil {
		return nil
	}
	switch order := compareTuple(key, node.key); {
	case order < 0:
		return tupleRebalance(newTupleNode(node.key, node.value, tupleDelete(node.left, key), node.right))
	case order > 0:
		return tupleRebalance(newTupleNode(node.key, node.value, node.left, tupleDelete(node.right, key)))
	case node.left == nil:
		return node.right
	case node.right == nil:
		return node.left
	default:
		successor := tupleMin(node.right)
		return tupleRebalance(newTupleNode(successor.key, successor.value, node.left, tupleDelete(node.right, successor.key)))
	}
}

func queryTupleBucket(node *tupleNode, resource dsl.EntityRef, relation string, visit func(policyengine.RelationshipTuple) bool) bool {
	if node == nil {
		return true
	}
	switch order := compareTupleBucket(node.key, resource, relation); {
	case order < 0:
		return queryTupleBucket(node.right, resource, relation, visit)
	case order > 0:
		return queryTupleBucket(node.left, resource, relation, visit)
	default:
		return queryTupleBucket(node.left, resource, relation, visit) && visit(node.value) && queryTupleBucket(node.right, resource, relation, visit)
	}
}

// Attributes are stored as a structurally-typed entity tree whose values are
// immutable segment tries. No path is ever flattened into a string.
type attributeEntityNode struct {
	left, right *attributeEntityNode
	height      int
	entity      dsl.EntityRef
	trie        *attributeTrie
}

type attributeTrie struct {
	attribute policyengine.Attribute
	hasValue  bool
	children  *segmentNode
}

type segmentNode struct {
	left, right *segmentNode
	height      int
	segment     string
	child       *attributeTrie
}

func entityHeight(node *attributeEntityNode) int {
	if node == nil {
		return 0
	}
	return node.height
}
func newEntityNode(entity dsl.EntityRef, trie *attributeTrie, left, right *attributeEntityNode) *attributeEntityNode {
	return &attributeEntityNode{entity: entity, trie: trie, left: left, right: right, height: 1 + max(entityHeight(left), entityHeight(right))}
}
func entityBalance(node *attributeEntityNode) int {
	return entityHeight(node.left) - entityHeight(node.right)
}
func entityRotateRight(node *attributeEntityNode) *attributeEntityNode {
	pivot := node.left
	return newEntityNode(pivot.entity, pivot.trie, pivot.left, newEntityNode(node.entity, node.trie, pivot.right, node.right))
}
func entityRotateLeft(node *attributeEntityNode) *attributeEntityNode {
	pivot := node.right
	return newEntityNode(pivot.entity, pivot.trie, newEntityNode(node.entity, node.trie, node.left, pivot.left), pivot.right)
}
func entityRebalance(node *attributeEntityNode) *attributeEntityNode {
	if entityBalance(node) > 1 {
		if entityBalance(node.left) < 0 {
			node = newEntityNode(node.entity, node.trie, entityRotateLeft(node.left), node.right)
		}
		return entityRotateRight(node)
	}
	if entityBalance(node) < -1 {
		if entityBalance(node.right) > 0 {
			node = newEntityNode(node.entity, node.trie, node.left, entityRotateRight(node.right))
		}
		return entityRotateLeft(node)
	}
	return node
}
func entityGet(node *attributeEntityNode, entity dsl.EntityRef) *attributeTrie {
	for node != nil {
		switch order := compareEntity(entity, node.entity); {
		case order < 0:
			node = node.left
		case order > 0:
			node = node.right
		default:
			return node.trie
		}
	}
	return nil
}
func entitySet(node *attributeEntityNode, entity dsl.EntityRef, trie *attributeTrie) *attributeEntityNode {
	if node == nil {
		return newEntityNode(entity, trie, nil, nil)
	}
	switch order := compareEntity(entity, node.entity); {
	case order < 0:
		return entityRebalance(newEntityNode(node.entity, node.trie, entitySet(node.left, entity, trie), node.right))
	case order > 0:
		return entityRebalance(newEntityNode(node.entity, node.trie, node.left, entitySet(node.right, entity, trie)))
	default:
		return newEntityNode(entity, trie, node.left, node.right)
	}
}

func entityMin(node *attributeEntityNode) *attributeEntityNode {
	for node.left != nil {
		node = node.left
	}
	return node
}

func entityDelete(node *attributeEntityNode, entity dsl.EntityRef) *attributeEntityNode {
	if node == nil {
		return nil
	}
	switch order := compareEntity(entity, node.entity); {
	case order < 0:
		return entityRebalance(newEntityNode(node.entity, node.trie, entityDelete(node.left, entity), node.right))
	case order > 0:
		return entityRebalance(newEntityNode(node.entity, node.trie, node.left, entityDelete(node.right, entity)))
	case node.left == nil:
		return node.right
	case node.right == nil:
		return node.left
	default:
		successor := entityMin(node.right)
		return entityRebalance(newEntityNode(successor.entity, successor.trie, node.left, entityDelete(node.right, successor.entity)))
	}
}

func segmentHeight(node *segmentNode) int {
	if node == nil {
		return 0
	}
	return node.height
}
func newSegmentNode(segment string, child *attributeTrie, left, right *segmentNode) *segmentNode {
	return &segmentNode{segment: segment, child: child, left: left, right: right, height: 1 + max(segmentHeight(left), segmentHeight(right))}
}
func segmentBalance(node *segmentNode) int {
	return segmentHeight(node.left) - segmentHeight(node.right)
}
func segmentRotateRight(node *segmentNode) *segmentNode {
	p := node.left
	return newSegmentNode(p.segment, p.child, p.left, newSegmentNode(node.segment, node.child, p.right, node.right))
}
func segmentRotateLeft(node *segmentNode) *segmentNode {
	p := node.right
	return newSegmentNode(p.segment, p.child, newSegmentNode(node.segment, node.child, node.left, p.left), p.right)
}
func segmentRebalance(node *segmentNode) *segmentNode {
	if segmentBalance(node) > 1 {
		if segmentBalance(node.left) < 0 {
			node = newSegmentNode(node.segment, node.child, segmentRotateLeft(node.left), node.right)
		}
		return segmentRotateRight(node)
	}
	if segmentBalance(node) < -1 {
		if segmentBalance(node.right) > 0 {
			node = newSegmentNode(node.segment, node.child, node.left, segmentRotateRight(node.right))
		}
		return segmentRotateLeft(node)
	}
	return node
}
func segmentGet(node *segmentNode, segment string) *attributeTrie {
	for node != nil {
		switch order := cmp.Compare(segment, node.segment); {
		case order < 0:
			node = node.left
		case order > 0:
			node = node.right
		default:
			return node.child
		}
	}
	return nil
}
func segmentSet(node *segmentNode, segment string, child *attributeTrie) *segmentNode {
	if node == nil {
		return newSegmentNode(segment, child, nil, nil)
	}
	switch order := cmp.Compare(segment, node.segment); {
	case order < 0:
		return segmentRebalance(newSegmentNode(node.segment, node.child, segmentSet(node.left, segment, child), node.right))
	case order > 0:
		return segmentRebalance(newSegmentNode(node.segment, node.child, node.left, segmentSet(node.right, segment, child)))
	default:
		return newSegmentNode(segment, child, node.left, node.right)
	}
}

func segmentMin(node *segmentNode) *segmentNode {
	for node.left != nil {
		node = node.left
	}
	return node
}

func segmentDelete(node *segmentNode, segment string) *segmentNode {
	if node == nil {
		return nil
	}
	switch order := cmp.Compare(segment, node.segment); {
	case order < 0:
		return segmentRebalance(newSegmentNode(node.segment, node.child, segmentDelete(node.left, segment), node.right))
	case order > 0:
		return segmentRebalance(newSegmentNode(node.segment, node.child, node.left, segmentDelete(node.right, segment)))
	case node.left == nil:
		return node.right
	case node.right == nil:
		return node.left
	default:
		successor := segmentMin(node.right)
		return segmentRebalance(newSegmentNode(successor.segment, successor.child, node.left, segmentDelete(node.right, successor.segment)))
	}
}

func trieSet(node *attributeTrie, path []string, index int, attribute policyengine.Attribute) (*attributeTrie, bool) {
	if node == nil {
		node = &attributeTrie{}
	}
	if index == len(path) {
		if node.children != nil {
			return nil, false
		}
		return &attributeTrie{attribute: attribute, hasValue: true, children: node.children}, true
	}
	if node.hasValue {
		return nil, false
	}
	child := segmentGet(node.children, path[index])
	updated, ok := trieSet(child, path, index+1, attribute)
	if !ok {
		return nil, false
	}
	return &attributeTrie{attribute: node.attribute, hasValue: node.hasValue, children: segmentSet(node.children, path[index], updated)}, true
}

func trieGet(node *attributeTrie, path []string) (policyengine.Attribute, bool) {
	for _, segment := range path {
		if node == nil {
			return policyengine.Attribute{}, false
		}
		node = segmentGet(node.children, segment)
	}
	if node == nil || !node.hasValue {
		return policyengine.Attribute{}, false
	}
	return node.attribute, true
}

func trieDelete(node *attributeTrie, path []string, index int) *attributeTrie {
	if node == nil {
		return nil
	}
	if index == len(path) {
		if node.children == nil {
			return nil
		}
		return &attributeTrie{children: node.children}
	}
	child := segmentGet(node.children, path[index])
	if child == nil {
		return node
	}
	updatedChild := trieDelete(child, path, index+1)
	children := node.children
	if updatedChild == nil {
		children = segmentDelete(children, path[index])
	} else {
		children = segmentSet(children, path[index], updatedChild)
	}
	if !node.hasValue && children == nil {
		return nil
	}
	return &attributeTrie{attribute: node.attribute, hasValue: node.hasValue, children: children}
}

func attributeSet(root *attributeEntityNode, attribute policyengine.Attribute) (*attributeEntityNode, bool) {
	entity := attribute.Entity()
	trie := entityGet(root, entity)
	updated, ok := trieSet(trie, attribute.Path(), 0, attribute)
	if !ok {
		return root, false
	}
	return entitySet(root, entity, updated), true
}
func attributeDelete(root *attributeEntityNode, key policyengine.AttributeKey) *attributeEntityNode {
	trie := entityGet(root, key.Entity())
	if trie == nil {
		return root
	}
	updated := trieDelete(trie, key.Path(), 0)
	if updated == nil {
		return entityDelete(root, key.Entity())
	}
	return entitySet(root, key.Entity(), updated)
}
func attributeGet(root *attributeEntityNode, key policyengine.AttributeKey) (policyengine.Attribute, bool) {
	return trieGet(entityGet(root, key.Entity()), key.Path())
}
