package guard

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// RenderJSON writes the report as indented JSON.
func RenderJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// RenderTable writes a human-readable table plus a one-line summary.
func RenderTable(w io.Writer, rep *Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LOG GROUP\tRETENTION\tSTORED\tSTATUS")
	for _, f := range rep.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			f.LogGroup, retentionLabel(f.RetentionDays), humanBytes(f.StoredBytes), statusLabel(f))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	total, unbounded, over := rep.Counts()
	fmt.Fprintf(w, "\n%d group(s), %d violation(s) (%d unbounded, %d over-threshold)\n",
		total, unbounded+over, unbounded, over)
	return nil
}

func statusLabel(f Finding) string {
	if f.Fixed && f.NewRetention != nil {
		return fmt.Sprintf("fixed -> %dd", *f.NewRetention)
	}
	return string(f.Status)
}

func retentionLabel(d *int32) string {
	if d == nil {
		return "never"
	}
	return fmt.Sprintf("%dd", *d)
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
