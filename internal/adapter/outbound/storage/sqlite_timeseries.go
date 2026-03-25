package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

// Compile-time check.
var _ storage.TimeSeriesStore = (*SQLiteTimeSeriesStore)(nil)

// SQLiteTimeSeriesStore implements TimeSeriesStore using embedded SQLite.
// Uses WAL mode for concurrent read/write and indexes for efficient range queries.
type SQLiteTimeSeriesStore struct {
	db   *sql.DB
	path string
}

// NewSQLiteTimeSeriesStore creates a new SQLite-backed time-series store.
// The path should end in .db; use ":memory:" for testing.
func NewSQLiteTimeSeriesStore(path string) (*SQLiteTimeSeriesStore, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=FULL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// SQLite allows only one writer at a time; serializing all access via a
	// single connection avoids SQLITE_BUSY under concurrent write load.
	db.SetMaxOpenConns(1)

	if err := initTimeSeriesSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	// Restrict file permissions to owner-only (0600).
	// Runs after initTimeSeriesSchema so WAL/SHM files exist.
	// On Windows os.Chmod is a no-op for Unix permission bits.
	if path != ":memory:" {
		if chmodErr := os.Chmod(path, 0600); chmodErr != nil {
			slog.Warn("failed to set sqlite file permissions", "path", path, "error", chmodErr)
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			_ = os.Chmod(path+suffix, 0600)
		}
	}

	return &SQLiteTimeSeriesStore{db: db, path: path}, nil
}

func initTimeSeriesSchema(db *sql.DB) error {
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS timeseries (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			series    TEXT    NOT NULL,
			timestamp INTEGER NOT NULL,
			value     REAL    NOT NULL DEFAULT 0,
			tags      TEXT,
			payload   BLOB
		);
		CREATE INDEX IF NOT EXISTS idx_ts_series_time ON timeseries(series, timestamp);
	`)
	return err
}

func (s *SQLiteTimeSeriesStore) Append(ctx context.Context, series string, point storage.DataPoint) error {
	var tagsJSON []byte
	if len(point.Tags) > 0 {
		var err error
		tagsJSON, err = json.Marshal(point.Tags)
		if err != nil {
			return fmt.Errorf("marshal tags: %w", err)
		}
	}

	ts := point.Timestamp.UnixMilli()
	if point.Timestamp.IsZero() {
		ts = time.Now().UnixMilli()
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO timeseries (series, timestamp, value, tags, payload) VALUES (?, ?, ?, ?, ?)`,
		series, ts, point.Value, tagsJSON, point.Payload,
	)
	return err
}

func (s *SQLiteTimeSeriesStore) Query(ctx context.Context, series string, from, to time.Time) ([]storage.DataPoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT timestamp, value, tags, payload FROM timeseries
		 WHERE series = ? AND timestamp >= ? AND timestamp <= ?
		 ORDER BY timestamp ASC`,
		series, from.UnixMilli(), to.UnixMilli(),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var points []storage.DataPoint
	for rows.Next() {
		var ts int64
		var value float64
		var tagsJSON sql.NullString
		var payload []byte

		if err := rows.Scan(&ts, &value, &tagsJSON, &payload); err != nil {
			return nil, err
		}

		dp := storage.DataPoint{
			Timestamp: time.UnixMilli(ts),
			Value:     value,
			Payload:   payload,
		}

		if tagsJSON.Valid && tagsJSON.String != "" {
			if err := json.Unmarshal([]byte(tagsJSON.String), &dp.Tags); err != nil {
				slog.Warn("sqlite_timeseries: failed to unmarshal tags JSON", "series", series, "error", err)
			}
		}

		points = append(points, dp)
	}
	return points, rows.Err()
}

func (s *SQLiteTimeSeriesStore) Aggregate(ctx context.Context, series string, from, to time.Time, fn storage.AggFunc) (float64, error) {
	var sqlFn string
	switch fn {
	case storage.AggSum:
		sqlFn = "SUM(value)"
	case storage.AggAvg:
		sqlFn = "AVG(value)"
	case storage.AggMin:
		sqlFn = "MIN(value)"
	case storage.AggMax:
		sqlFn = "MAX(value)"
	case storage.AggCount:
		sqlFn = "COUNT(*)"
	default:
		return 0, fmt.Errorf("unknown aggregate function: %s", fn)
	}

	var result sql.NullFloat64
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT %s FROM timeseries WHERE series = ? AND timestamp >= ? AND timestamp <= ?`, sqlFn),
		series, from.UnixMilli(), to.UnixMilli(),
	).Scan(&result)
	if err != nil {
		return 0, err
	}
	if !result.Valid {
		return 0, nil
	}
	return result.Float64, nil
}

func (s *SQLiteTimeSeriesStore) Prune(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan).UnixMilli()
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM timeseries WHERE timestamp < ?`, cutoff,
	)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("prune rows affected: %w", err)
	}
	return int(n), nil
}

func (s *SQLiteTimeSeriesStore) DeleteSeries(ctx context.Context, series string) (int, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM timeseries WHERE series = ?`, series,
	)
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete series rows affected: %w", err)
	}
	return int(n), nil
}

func (s *SQLiteTimeSeriesStore) Close() error {
	return s.db.Close()
}
