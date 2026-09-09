package store

import (
	"context"
	"testing"
	"time"
)

func TestCloudConnectionLifecycle(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{
			Name: "prod-eu", Provider: CloudProviderAWSACM,
			IsEnabled: true, SyncIntervalMinutes: 360,
			ConfigEncrypted: "sealed-blob",
		}
		if err := st.CreateCloudConnection(ctx, conn); err != nil {
			t.Fatalf("CreateCloudConnection: %v", err)
		}
		if conn.ID == "" {
			t.Fatal("the store must assign an id")
		}

		if err := st.CreateCloudConnection(ctx, &CloudConnection{
			Name: "PROD-EU", Provider: CloudProviderGCP, SyncIntervalMinutes: 360,
		}); err == nil {
			t.Error("two connections with the same name were accepted; one of them would be unreachable on screen")
		}

		// An edit is not a sync. Renaming a connection must not look like one that
		// has just answered, and it must not blank the credentials.
		stamp := time.Now()
		if err := st.MarkCloudConnectionSynced(ctx, conn.ID, stamp, stamp.Add(time.Hour),
			true, []string{"ACM in eu-west-1"}, 4, 3, ""); err != nil {
			t.Fatalf("MarkCloudConnectionSynced: %v", err)
		}

		edited, _ := st.GetCloudConnection(ctx, conn.ID)
		edited.Name = "prod-eu-west"
		edited.ConfigEncrypted = ""
		if err := st.UpdateCloudConnection(ctx, edited); err != nil {
			t.Fatalf("UpdateCloudConnection: %v", err)
		}

		after, err := st.GetCloudConnection(ctx, conn.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Name != "prod-eu-west" {
			t.Errorf("name = %q, want the edited one", after.Name)
		}
		if after.ConfigEncrypted != "sealed-blob" {
			t.Error("an edit with no new credentials blanked the stored ones")
		}
		if after.LastSuccessAt == nil {
			t.Error("an edit cleared the record of the last successful sync")
		}
		if after.CertificatesSeen != 4 || after.UnmanagedSeen != 3 {
			t.Errorf("counts = %d/%d, want 4/3 carried through the edit", after.CertificatesSeen, after.UnmanagedSeen)
		}
		if len(after.Scopes) != 1 {
			t.Errorf("scopes = %v, want the ones the sync recorded", after.Scopes)
		}
		if !after.CreatedAt.Equal(conn.CreatedAt) {
			t.Error("created_at moved on update")
		}

		if _, err := st.GetCloudConnection(ctx, "no-such-connection"); err == nil {
			t.Error("an unknown connection id must be an error, not an empty account")
		}
	})
}

// The split that makes silence readable, in its cloud form.
func TestCloudConnectionStaleness(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	hourly := 60

	fresh := &CloudConnection{IsEnabled: true, SyncIntervalMinutes: hourly,
		LastSuccessAt: timePtr(now.Add(-30 * time.Minute))}
	if fresh.Stale(now) {
		t.Error("a connection that answered half an hour ago reads as stale")
	}

	lapsed := &CloudConnection{IsEnabled: true, SyncIntervalMinutes: hourly,
		LastSuccessAt: timePtr(now.Add(-5 * time.Hour))}
	if !lapsed.Stale(now) {
		t.Error("a connection that has not answered in five hourly windows reads as healthy")
	}

	// A connection whose credentials expired weeks ago, still attempting every
	// hour, is the case this exists for: last_synced_at keeps moving.
	failing := &CloudConnection{IsEnabled: true, SyncIntervalMinutes: hourly,
		LastSyncedAt: timePtr(now.Add(-1 * time.Minute)),
		CreatedAt:    now.Add(-72 * time.Hour)}
	if !failing.Stale(now) {
		t.Error("a connection that attempts constantly and never succeeds reads as healthy")
	}

	brandNew := &CloudConnection{IsEnabled: true, SyncIntervalMinutes: hourly, CreatedAt: now.Add(-5 * time.Minute)}
	if brandNew.Stale(now) {
		t.Error("a connection created five minutes ago reads as stale")
	}

	off := &CloudConnection{IsEnabled: false, SyncIntervalMinutes: hourly, CreatedAt: now.Add(-72 * time.Hour)}
	if off.Stale(now) {
		t.Error("a disabled connection reads as stale")
	}
}

func TestCloudCertificateUpsertIsIdempotent(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{Name: "acm", Provider: CloudProviderAWSACM, SyncIntervalMinutes: 360}
		if err := st.CreateCloudConnection(ctx, conn); err != nil {
			t.Fatal(err)
		}

		first := time.Now().Add(-time.Hour)
		added, err := st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "arn:one", Name: "one",
				ManagementState: DiscoveryUnmanaged, LastSeenAt: first},
		})
		if err != nil {
			t.Fatalf("UpsertCloudCertificates: %v", err)
		}
		if len(added) != 1 {
			t.Fatalf("first sync reported %d new certificates, want 1", len(added))
		}

		// The second sync sees the same certificate. It is not new, and reporting
		// it as new is how an alert channel gets muted.
		second := time.Now()
		added, err = st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "arn:one", Name: "one-renamed",
				ManagementState: DiscoveryUnmanaged, LastSeenAt: second},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(added) != 0 {
			t.Errorf("the second sync reported %d new certificates, want 0", len(added))
		}

		certs, total, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{ConnectionID: conn.ID})
		if total != 1 {
			t.Fatalf("total = %d, want one row for one resource", total)
		}
		if certs[0].Name != "one-renamed" {
			t.Errorf("name = %q, want the value from the latest sync", certs[0].Name)
		}
		if !certs[0].FirstSeenAt.Before(second) {
			t.Error("first_seen_at was overwritten; when a certificate first appeared is the part worth keeping")
		}
	})
}

// A provider that answered with nothing is possible. So is a bug. Reporting an
// entire estate as deleted is the more expensive of the two mistakes.
func TestAnEmptySyncDoesNotWipeTheInventory(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{Name: "vault", Provider: CloudProviderAzureKeyVault, SyncIntervalMinutes: 360}
		_ = st.CreateCloudConnection(ctx, conn)
		_, _ = st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "cert-a", ManagementState: DiscoveryUnmanaged, LastSeenAt: time.Now()},
			{ConnectionID: conn.ID, ResourceID: "cert-b", ManagementState: DiscoveryUnmanaged, LastSeenAt: time.Now()},
		})

		removed, err := st.MarkCloudCertificatesRemoved(ctx, conn.ID, nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if removed != 0 {
			t.Fatalf("an empty seen list removed %d certificates", removed)
		}

		removed, err = st.MarkCloudCertificatesRemoved(ctx, conn.ID, []string{"cert-a"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if removed != 1 {
			t.Errorf("removed = %d, want the 1 the sync no longer saw", removed)
		}
	})
}

// Adopting a cloud certificate settles the question it raised. A later sync
// must not put the same work back on the list.
func TestImportSurvivesTheNextSync(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{Name: "cluster", Provider: CloudProviderKubernetes, SyncIntervalMinutes: 360}
		_ = st.CreateCloudConnection(ctx, conn)

		added, _ := st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "shop/tls", ManagementState: DiscoveryUnmanaged, LastSeenAt: time.Now()},
		})
		// A real certificate, not an invented id. matched_certificate_id is a
		// uuid column with a foreign key, and "cert-123" only ever worked
		// because these tests had never met a database.
		adopted := sampleCertificate("cloud-adopted")
		if err := st.CreateCertificate(ctx, adopted); err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		if err := st.MarkCloudCertificateImported(ctx, added[0].ID, adopted.ID); err != nil {
			t.Fatalf("MarkCloudCertificateImported: %v", err)
		}

		// The provider still reports it as unmanaged, because the provider has no
		// idea it was adopted.
		_, _ = st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "shop/tls", ManagementState: DiscoveryUnmanaged, LastSeenAt: time.Now()},
		})

		certs, _, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{ConnectionID: conn.ID})
		if len(certs) != 1 {
			t.Fatalf("got %d certificates, want 1", len(certs))
		}
		if !certs[0].IsImported {
			t.Error("the import was lost on the next sync")
		}
		if certs[0].ManagementState != DiscoveryManaged {
			t.Errorf("management state = %q after import, want MANAGED", certs[0].ManagementState)
		}

		outstanding, _, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{UnimportedOnly: true})
		if len(outstanding) != 0 {
			t.Errorf("an adopted certificate still appears as outstanding work: %+v", outstanding)
		}
	})
}

func TestCloudCertificateFiltering(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{Name: "acm", Provider: CloudProviderAWSACM, SyncIntervalMinutes: 360}
		_ = st.CreateCloudConnection(ctx, conn)

		soon := time.Now().Add(10 * 24 * time.Hour)
		later := time.Now().Add(300 * 24 * time.Hour)
		_, _ = st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "arn:a", ManagementState: DiscoveryUnmanaged,
				NotAfter: &later, LastSeenAt: time.Now(),
				Findings: []Finding{{Code: "will_not_renew", Severity: "INFO"}}},
			{ConnectionID: conn.ID, ResourceID: "arn:b", ManagementState: DiscoveryManaged,
				NotAfter: &soon, LastSeenAt: time.Now()},
		})

		cases := map[string]struct {
			filter CloudCertificateFilter
			want   int
		}{
			"everything":       {CloudCertificateFilter{ConnectionID: conn.ID}, 2},
			"unmanaged":        {CloudCertificateFilter{ManagementState: DiscoveryUnmanaged}, 1},
			"a finding":        {CloudCertificateFilter{FindingCode: "will_not_renew"}, 1},
			"a finding nobody": {CloudCertificateFilter{FindingCode: "weak_key"}, 0},
			// A well-formed id that matches nothing. The old value here was
			// "nope", which PostgreSQL refuses outright as a uuid — so the case
			// was testing the driver rather than the filter.
			"another account": {CloudCertificateFilter{ConnectionID: "00000000-0000-4000-8000-000000000000"}, 0},
		}
		for name, tc := range cases {
			got, total, err := st.ListCloudCertificates(ctx, tc.filter)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(got) != tc.want || int(total) != tc.want {
				t.Errorf("%s: got %d (total %d), want %d", name, len(got), total, tc.want)
			}
		}

		// Soonest to expire first: the list is read to decide what to deal with
		// today, not to browse an inventory.
		all, _, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{ConnectionID: conn.ID})
		if all[0].ResourceID != "arn:b" {
			t.Errorf("order = %s first; want the one expiring soonest", all[0].ResourceID)
		}
	})
}

// Reads must hand back copies. The sync engine writes while a dashboard reads.
func TestCloudReadsReturnCopies(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{Name: "acm", Provider: CloudProviderAWSACM, SyncIntervalMinutes: 360}
		_ = st.CreateCloudConnection(ctx, conn)
		_, _ = st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "arn:a", Name: "a", LastSeenAt: time.Now()},
		})

		got, _ := st.GetCloudConnection(ctx, conn.ID)
		got.Name = "TAMPERED"
		again, _ := st.GetCloudConnection(ctx, conn.ID)
		if again.Name == "TAMPERED" {
			t.Error("a caller mutated the stored connection through the record it was handed")
		}

		certs, _, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{ConnectionID: conn.ID})
		certs[0].Name = "TAMPERED"
		fresh, _, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{ConnectionID: conn.ID})
		if fresh[0].Name == "TAMPERED" {
			t.Error("a caller mutated a stored certificate through the slice it was handed")
		}
	})
}

// Deleting a connection takes its certificates with it. Orphaned rows would
// show as findings against an account nobody can look in.
func TestDeletingAConnectionRemovesItsCertificates(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		conn := &CloudConnection{Name: "acm", Provider: CloudProviderAWSACM, SyncIntervalMinutes: 360}
		_ = st.CreateCloudConnection(ctx, conn)
		_, _ = st.UpsertCloudCertificates(ctx, []*CloudCertificate{
			{ConnectionID: conn.ID, ResourceID: "arn:a", LastSeenAt: time.Now()},
		})

		if err := st.DeleteCloudConnection(ctx, conn.ID); err != nil {
			t.Fatal(err)
		}
		certs, total, _ := st.ListCloudCertificates(ctx, CloudCertificateFilter{})
		if len(certs) != 0 || total != 0 {
			t.Errorf("%d certificates survived their connection", len(certs))
		}
		if err := st.DeleteCloudConnection(ctx, conn.ID); err == nil {
			t.Error("deleting an unknown connection must fail rather than silently do nothing")
		}
	})
}
