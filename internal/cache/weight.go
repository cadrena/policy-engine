package cache

const approximateRevisionOverhead = int64(128)

func approximateRevisionBytes(key RevisionKey, encodedBytes int) int64 {
	return approximateRevisionOverhead +
		int64(len(key.namespace)) +
		int64(len(key.revision)) +
		int64(len(key.evaluatorABI)) +
		int64(encodedBytes)
}
