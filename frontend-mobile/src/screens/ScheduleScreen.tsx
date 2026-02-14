import React from 'react';
import { View, Text, StyleSheet, FlatList } from 'react-native';

export default function ScheduleScreen() {
  const events = [
    { id: '1', title: 'Breakfast', time: '8:00 AM' },
    { id: '2', title: 'Client Meeting', time: '10:30 AM' },
    { id: '3', title: 'Lunch', time: '1:00 PM' },
  ];

  return (
    <View style={styles.container}>
      <Text style={styles.header}>Today's Schedule</Text>
      <FlatList
        data={events}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <View style={styles.eventItem}>
            <Text style={styles.eventTitle}>{item.title}</Text>
            <Text style={styles.eventTime}>{item.time}</Text>
          </View>
        )}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#f9f9f9',
  },
  header: {
    fontSize: 22,
    fontWeight: '700',
    marginBottom: 20,
  },
  eventItem: {
    backgroundColor: '#fff',
    padding: 15,
    borderRadius: 10,
    marginBottom: 10,
    borderLeftWidth: 5,
    borderLeftColor: '#007AFF',
  },
  eventTitle: {
    fontSize: 18,
    fontWeight: '600',
  },
  eventTime: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
});
