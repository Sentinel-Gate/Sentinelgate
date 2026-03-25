package storage

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

func newTestTimeSeriesStore(t *testing.T) *SQLiteTimeSeriesStore {
	t.Helper()
	s, err := NewSQLiteTimeSeriesStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteTimeSeriesStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTimeSeriesStore_AppendAndQuery(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)

	points := []storage.DataPoint{
		{Timestamp: now.Add(-2 * time.Hour), Value: 10},
		{Timestamp: now.Add(-1 * time.Hour), Value: 20},
		{Timestamp: now, Value: 30},
	}

	for _, p := range points {
		if err := s.Append(ctx, "cpu.usage", p); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Query all.
	result, err := s.Query(ctx, "cpu.usage", now.Add(-3*time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("got %d points, want 3", len(result))
	}

	// Verify order (ascending).
	if result[0].Value != 10 || result[1].Value != 20 || result[2].Value != 30 {
		t.Errorf("unexpected values: %v", result)
	}
}

func TestTimeSeriesStore_QueryTimeRange(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)

	_ = s.Append(ctx, "series", storage.DataPoint{Timestamp: now.Add(-3 * time.Hour), Value: 1})
	_ = s.Append(ctx, "series", storage.DataPoint{Timestamp: now.Add(-1 * time.Hour), Value: 2})
	_ = s.Append(ctx, "series", storage.DataPoint{Timestamp: now, Value: 3})

	// Query only the middle hour.
	result, err := s.Query(ctx, "series", now.Add(-2*time.Hour), now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d points, want 1", len(result))
	}
	if result[0].Value != 2 {
		t.Errorf("value = %v, want 2", result[0].Value)
	}
}

func TestTimeSeriesStore_SeriesIsolation(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)

	_ = s.Append(ctx, "series-a", storage.DataPoint{Timestamp: now, Value: 100})
	_ = s.Append(ctx, "series-b", storage.DataPoint{Timestamp: now, Value: 200})

	a, _ := s.Query(ctx, "series-a", now.Add(-time.Hour), now.Add(time.Hour))
	b, _ := s.Query(ctx, "series-b", now.Add(-time.Hour), now.Add(time.Hour))

	if len(a) != 1 || a[0].Value != 100 {
		t.Errorf("series-a: got %v", a)
	}
	if len(b) != 1 || b[0].Value != 200 {
		t.Errorf("series-b: got %v", b)
	}
}

func TestTimeSeriesStore_Tags(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	tags := map[string]string{"agent": "claude", "region": "eu"}
	_ = s.Append(ctx, "calls", storage.DataPoint{Timestamp: now, Value: 42, Tags: tags})

	result, _ := s.Query(ctx, "calls", now.Add(-time.Hour), now.Add(time.Hour))
	if len(result) != 1 {
		t.Fatalf("got %d points", len(result))
	}
	if result[0].Tags["agent"] != "claude" {
		t.Errorf("tags = %v", result[0].Tags)
	}
}

func TestTimeSeriesStore_Payload(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	payload := json.RawMessage(`{"tool":"read_file","count":5}`)
	_ = s.Append(ctx, "tools", storage.DataPoint{Timestamp: now, Value: 5, Payload: payload})

	result, _ := s.Query(ctx, "tools", now.Add(-time.Hour), now.Add(time.Hour))
	if len(result) != 1 {
		t.Fatalf("got %d points", len(result))
	}
	if string(result[0].Payload) != `{"tool":"read_file","count":5}` {
		t.Errorf("payload = %s", result[0].Payload)
	}
}

func TestTimeSeriesStore_AggregateSum(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now, Value: 10})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(time.Second), Value: 20})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(2 * time.Second), Value: 30})

	sum, err := s.Aggregate(ctx, "s", now.Add(-time.Hour), now.Add(time.Hour), storage.AggSum)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if sum != 60 {
		t.Errorf("sum = %v, want 60", sum)
	}
}

func TestTimeSeriesStore_AggregateAvg(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now, Value: 10})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(time.Second), Value: 20})

	avg, err := s.Aggregate(ctx, "s", now.Add(-time.Hour), now.Add(time.Hour), storage.AggAvg)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if avg != 15 {
		t.Errorf("avg = %v, want 15", avg)
	}
}

func TestTimeSeriesStore_AggregateMinMax(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now, Value: 5})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(time.Second), Value: 15})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(2 * time.Second), Value: 10})

	min, _ := s.Aggregate(ctx, "s", now.Add(-time.Hour), now.Add(time.Hour), storage.AggMin)
	max, _ := s.Aggregate(ctx, "s", now.Add(-time.Hour), now.Add(time.Hour), storage.AggMax)

	if min != 5 {
		t.Errorf("min = %v, want 5", min)
	}
	if max != 15 {
		t.Errorf("max = %v, want 15", max)
	}
}

func TestTimeSeriesStore_AggregateCount(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now, Value: 1})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(time.Second), Value: 2})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(2 * time.Second), Value: 3})

	count, _ := s.Aggregate(ctx, "s", now.Add(-time.Hour), now.Add(time.Hour), storage.AggCount)
	if count != 3 {
		t.Errorf("count = %v, want 3", count)
	}
}

func TestTimeSeriesStore_AggregateEmptySeries(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now()
	sum, err := s.Aggregate(ctx, "empty", now.Add(-time.Hour), now.Add(time.Hour), storage.AggSum)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if sum != 0 {
		t.Errorf("empty sum = %v, want 0", sum)
	}
}

func TestTimeSeriesStore_Prune(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Millisecond)

	// Insert old and new data.
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(-48 * time.Hour), Value: 1})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now.Add(-47 * time.Hour), Value: 2})
	_ = s.Append(ctx, "s", storage.DataPoint{Timestamp: now, Value: 3})

	pruned, err := s.Prune(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 2 {
		t.Errorf("pruned = %d, want 2", pruned)
	}

	remaining, _ := s.Query(ctx, "s", now.Add(-72*time.Hour), now.Add(time.Hour))
	if len(remaining) != 1 {
		t.Fatalf("remaining = %d, want 1", len(remaining))
	}
	if remaining[0].Value != 3 {
		t.Errorf("remaining value = %v, want 3", remaining[0].Value)
	}
}

func TestTimeSeriesStore_QueryEmptySeries(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now()
	result, err := s.Query(ctx, "nonexistent", now.Add(-time.Hour), now)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}
}

func TestTimeSeriesStore_AggregateInvalidFunc(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	now := time.Now()
	_, err := s.Aggregate(ctx, "s", now, now, "invalid")
	if err == nil {
		t.Error("expected error for invalid aggregate function")
	}
}

func TestTimeSeriesStore_LargeDataSet(t *testing.T) {
	s := newTestTimeSeriesStore(t)
	ctx := context.Background()

	base := time.Now().Truncate(time.Millisecond)

	// Insert 1000 points.
	for i := 0; i < 1000; i++ {
		_ = s.Append(ctx, "load", storage.DataPoint{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Value:     float64(i),
		})
	}

	// Query all.
	result, err := s.Query(ctx, "load", base.Add(-time.Hour), base.Add(2000*time.Second))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(result) != 1000 {
		t.Fatalf("got %d points, want 1000", len(result))
	}

	// Verify ascending order.
	for i := 1; i < len(result); i++ {
		if result[i].Timestamp.Before(result[i-1].Timestamp) {
			t.Fatal("results not in ascending order")
		}
	}

	// Aggregate.
	sum, _ := s.Aggregate(ctx, "load", base.Add(-time.Hour), base.Add(2000*time.Second), storage.AggSum)
	expected := float64(999 * 1000 / 2) // sum of 0..999
	if math.Abs(sum-expected) > 0.01 {
		t.Errorf("sum = %v, want %v", sum, expected)
	}
}
